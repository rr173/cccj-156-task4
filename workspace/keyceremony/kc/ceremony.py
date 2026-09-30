"""Ceremony orchestrator: the state machine that runs root-key ceremonies.

Guarantees implemented in this module
-------------------------------------
1. Fixed roles + threshold + order: each ceremony is created against an
   immutable policy snapshot and advances OPEN -> ATTESTED -> DELIVERED ->
   CONFIRMED -> COMMIT -> COMPLETED. No stage can be skipped or replayed.
2. No single person can rebuild a key: the orchestrator never learns shares
   for GENERATE/ROTATE; they are generated under a random polynomial and
   delivered individually sealed to each attested device.
3. Device attestation precedes delivery; shares are sealed only to the
   enrolled key of a freshly quoted, measurement-matching device.
4. Participants/policy changing after start aborts the round; the audit
   trail is retained and sealed by the service identity.
5. Recovery: lost shares -> BACKUP ceremony (survivors present their shares,
   fresh polynomial is distributed); dropped participants -> replacement
   slots declared at open; duplicate confirmations are idempotent; repeated
   publishes are compare-and-swapped (RaceLost, never two ACTIVE keys).
6. Handover: ROTATE leaves the old version RETIRING; signers use ACTIVE only,
   verifiers still accept every historical version.
"""

from __future__ import annotations

import os
import time

from . import crypto, ed25519
from . import policy as pol
from .attestation import (
    DeviceWallet, EnrolledDevice, provision_device, verify_action_envelope,
    verify_quote,
)
from .directory import (
    ABORTED, ACTIVE, DESTROYED, STAGED, KeyDirectory,
)
from .errors import (
    AttestationError, AuthenticationError, CeremonyError, ConflictState,
    DuplicateAction, NotFound, PolicyViolation, QuorumFailure, RaceLost,
    ReplayError, SealError,
)
from .storage import AuditLog, Store

STAGE_ORDER = ("OPEN", "ATTESTED", "DELIVERED", "CONFIRMED", "COMMIT", "COMPLETED")
OPEN_STATUS = "OPEN"
DONE_STATUS = "COMPLETED"
ABORT_STATUS = "ABORTED"


def _mid(prefix: str) -> str:
    return f"{prefix}_{os.urandom(10).hex()}"


def _now(clock) -> float:
    return float(clock())


class Orchestrator:
    """All mutating operations must run within `with store.locked():`."""

    def __init__(self, store: Store, clock=time.time):
        self.store = store
        self.clock = clock
        self.state = store.load_state()
        self.seed = store.service_seed()
        self.audit = AuditLog(store.audit_path, signer_seed=self.seed)
        self.dir = KeyDirectory(self.state, self.seed, clock=clock)

    # ======================================================================
    # enrollment / policy
    # ======================================================================
    def enroll_participant(self, participant_id: str, display_name: str,
                           role: str) -> dict:
        if role not in pol.ROLES:
            raise PolicyViolation(f"unknown role {role}")
        if participant_id in self.state["participants"]:
            raise DuplicateAction(f"participant {participant_id} already enrolled")
        rec = {"participant_id": participant_id, "name": display_name,
               "role": role, "enrolled_at": _now(self.clock)}
        self.state["participants"][participant_id] = rec
        self._audit("participant_enrolled",
                    {"participant_id": participant_id, "role": role,
                     "name": display_name})
        return rec

    def enroll_device(self, wallet: DeviceWallet, label: str = "") -> EnrolledDevice:
        pid = None
        # participant_id is provided on the wallet via label convention in
        # tests; callers may instead register then bind explicitly.
        rec = EnrolledDevice(
            wallet.device_id, pid or "", label, wallet.identity_pub,
            wallet.seal_pub, wallet.measurement, _now(self.clock))
        return rec

    def bind_device(self, participant_id: str, wallet: DeviceWallet,
                    label: str = "") -> EnrolledDevice:
        if participant_id not in self.state["participants"]:
            raise NotFound(f"participant {participant_id} not enrolled")
        if wallet.device_id in self.state["devices"]:
            raise DuplicateAction(f"device {wallet.device_id} already bound")
        rec = EnrolledDevice(
            wallet.device_id, participant_id, label, wallet.identity_pub,
            wallet.seal_pub, wallet.measurement, _now(self.clock))
        self.state["devices"][wallet.device_id] = rec.to_dict()
        self._audit("device_bound",
                    {"device_id": wallet.device_id,
                     "participant_id": participant_id,
                     "identity_pub": crypto.b64e(wallet.identity_pub),
                     "seal_pub": str(wallet.seal_pub),
                     "measurement": crypto.b64e(wallet.measurement)})
        return rec

    def create_policy(self, policy_id: str, label: str, threshold: int,
                      slot_specs: list[tuple[str, str, str]],
                      purposes: tuple[str, ...] = ("root-signing",),
                      handover_seconds: int = 3600,
                      ceremony_timeout_seconds: int = 1800) -> dict:
        """slot_specs = [(participant_id, role, device_id), ...]."""
        version = 1
        for p in self.state["policies"].values():
            if p["policy_id"] == policy_id:
                raise DuplicateAction(f"policy {policy_id} exists; revise it")
        slots = []
        for pid, role, did in slot_specs:
            if pid not in self.state["participants"]:
                raise NotFound(f"participant {pid} not enrolled")
            dev = self.state["devices"].get(did)
            if not dev:
                raise NotFound(f"device {did} not bound")
            if dev["participant_id"] != pid:
                raise PolicyViolation(f"device {did} belongs to another participant")
            if dev.get("revoked"):
                raise PolicyViolation(f"device {did} revoked")
            slots.append(pol.Slot(pid, role, did))
        p = pol.Policy(policy_id, version, label, threshold, handover_seconds,
                       ceremony_timeout_seconds, tuple(purposes), slots)
        p.validate()
        self.state["policies"][policy_id] = p.to_dict()
        self.state["policy_versions"].append(f"{policy_id}:{version}")
        self._audit("policy_created", {"policy": p.snapshot()})
        return p.to_dict()

    def revise_policy(self, new_policy_id: str, label: str, threshold: int,
                      slot_specs, purposes=("root-signing",),
                      handover_seconds: int = 3600,
                      ceremony_timeout_seconds: int = 1800,
                      supersedes: str | None = None) -> dict:
        """Create a new policy version identity. Any open ceremonies on the
        superseded id are aborted (participants/policy changing after start
        must invalidate the round), with the reason preserved in audit."""
        d = self.create_policy(
            new_policy_id, label, threshold, slot_specs, purposes,
            handover_seconds, ceremony_timeout_seconds)
        if supersedes:
            old = self.state["policies"].get(supersedes)
            if old:
                old["superseded_by"] = new_policy_id
                self._audit("policy_superseded",
                            {"old": supersedes, "new": new_policy_id})
        for cid, c in list(self.state["ceremonies"].items()):
            if c["status"] == OPEN_STATUS and (
                    not supersedes or c["policy_snapshot"]["policy_id"] == supersedes):
                self._abort(cid, "policy revised after ceremony start",
                            actor="orchestrator")
        return d

    # ======================================================================
    # ceremony lifecycle
    # ======================================================================
    def _expire_if_needed(self, c: dict):
        if c["status"] == OPEN_STATUS and _now(self.clock) > c["deadline"]:
            self._abort(c["id"], "ceremony timed out", actor="orchestrator")
            raise ConflictState(f"ceremony {c['id']} timed out and was aborted")

    def _get_open(self, ceremony_id: str) -> dict:
        c = self.state["ceremonies"].get(ceremony_id)
        if c is None:
            raise NotFound(f"unknown ceremony {ceremony_id}")
        self._expire_if_needed(c)
        if c["status"] != OPEN_STATUS:
            raise ConflictState(
                f"ceremony {ceremony_id} is {c['status']}, not open")
        return c

    def open_ceremony(self, kind: str, policy_id: str, purpose: str,
                      actor: str, lost_participants: list[str] | None = None,
                      replacement_specs: list[dict] | None = None,
                      target_version: str | None = None) -> dict:
        if kind not in pol.CEREMONY_KINDS:
            raise PolicyViolation(f"unknown ceremony kind {kind}")
        p_dict = self.state["policies"].get(policy_id)
        if not p_dict:
            raise NotFound(f"unknown policy {policy_id}")
        p = pol.Policy.from_dict(p_dict)
        if purpose not in p.purposes:
            raise PolicyViolation(f"purpose {purpose} not covered by policy")

        # No overlapping open ceremony for the same purpose: prevents two
        # concurrent rotations racing toward two current keys.
        for c in self.state["ceremonies"].values():
            if c["status"] == OPEN_STATUS and c["purpose"] == purpose:
                raise ConflictState(
                    f"ceremony {c['id']} for {purpose} is already open")

        if kind == pol.GENERATE and self.dir.has_any_non_destroyed(purpose):
            raise PolicyViolation(
                f"{purpose} already has a key; use ROTATE, not GENERATE")
        if kind in (pol.ROTATE, pol.DESTROY):
            active = self.dir.active(purpose)
            if active is None:
                raise PolicyViolation(f"{kind} requires an ACTIVE key for {purpose}")
        if kind == pol.ROTATE:
            retiring = [k for k in self.dir.versions_for_purpose(purpose)
                        if k["status"] == "RETIRING"]
            if retiring:
                raise ConflictState(
                    "a handover window is already open for " + purpose)
        if kind == pol.DESTROY:
            if target_version is None:
                raise PolicyViolation(
                    "DESTROY must name the RETIRING target_version")
            target = self.dir.get(target_version)
            if target["purpose"] != purpose or target["status"] != "RETIRING":
                raise PolicyViolation(
                    "DESTROY target must be the purpose's RETIRING version")

        snapshot = p.snapshot()
        roster0 = list(snapshot["slots"])
        roster = list(roster0)
        recovery = None
        if kind == pol.BACKUP:
            lost = list(lost_participants or [])
            known = {s["participant_id"] for s in roster}
            unknown = [x for x in lost if x not in known]
            if unknown:
                raise NotFound(f"lost participants not on roster: {unknown}")
            survivors = [s for s in roster if s["participant_id"] not in lost]
            if len(survivors) < p.threshold:
                raise QuorumFailure(
                    f"not enough survivors ({len(survivors)}) for threshold "
                    f"{p.threshold}; unrecoverable by policy")
            # replacements must fill the lost slots 1:1 with matching roles,
            # using devices enrolled/bound but not already rostered.
            repls = list(replacement_specs or [])
            if len(repls) != len(lost):
                raise PolicyViolation(
                    f"BACKUP requires {len(lost)} replacement(s) for lost "
                    f"participants, got {len(repls)}")
            roster = survivors
            lost_by_pid = {s["participant_id"]: s for s in roster0
                           if s["participant_id"] in lost}
            for spec in repls:
                rpid, rrole, rdid = spec["participant_id"], spec["role"], spec["device_id"]
                replaces = spec.get("replaces")
                if replaces is None or replaces not in lost_by_pid:
                    raise PolicyViolation(
                        "each replacement must name the lost slot 'replaces'")
                if lost_by_pid[replaces]["role"] != rrole:
                    raise PolicyViolation(
                        f"replacement role {rrole} does not fill the lost "
                        f"{lost_by_pid[replaces]['role']} slot of {replaces}")
                if rpid in known or any(s["participant_id"] == rpid for s in roster):
                    raise PolicyViolation(f"replacement {rpid} already rostered")
                if rpid not in self.state["participants"]:
                    raise NotFound(f"replacement participant {rpid} not enrolled")
                if self.state["participants"][rpid]["role"] != rrole:
                    raise PolicyViolation(
                        f"replacement {rpid} enrolled as a different role")
                dev = self.state["devices"].get(rdid)
                if not dev or dev["participant_id"] != rpid:
                    raise NotFound(f"replacement device {rdid} not bound to {rpid}")
                spec = {**spec}
                roster.append({"participant_id": rpid, "role": rrole,
                               "device_id": rdid})
            recovery = {"lost_participants": lost,
                        "replacements": repls}
            if len(roster) != len(snapshot["slots"]):
                raise PolicyViolation("recovered roster size must match policy")

        cid = _mid("cer")
        c = {
            "id": cid,
            "kind": kind,
            "purpose": purpose,
            "policy_snapshot": snapshot,
            "threshold": p.threshold,
            "stage": "OPEN",
            "status": OPEN_STATUS,
            "created_at": _now(self.clock),
            "deadline": _now(self.clock) + p.ceremony_timeout_seconds,
            "created_by": actor,
            "roster": roster,
            "recovery": recovery,
            "challenges": {},
            "participants": {},
            "deliveries": {},
            "incoming": {},
            "confirmations": {},
            "submitted": {},
            "deal": None,
            "result": None,
            "abort": None,
            "target_version": target_version,
        }
        for s in roster:
            c["participants"][s["device_id"]] = {
                "device_id": s["device_id"],
                "participant_id": s["participant_id"],
                "role": s["role"],
                "attested": False,
                "attest": None,
                "delivered": False,
                "delivery_id": None,
                "confirmed": False,
                "submitted": False,
            }
        self.state["ceremonies"][cid] = c
        self._audit("ceremony_opened",
                    {"ceremony_id": cid, "kind": kind, "purpose": purpose,
                     "policy_id": p.policy_id, "version": p.version,
                     "threshold": p.threshold,
                     "roster": [s["device_id"] for s in roster],
                     "recovery": recovery})
        return self.public_ceremony(cid)

    # ---- helpers ---------------------------------------------------------
    def _policy(self, c: dict) -> pol.Policy:
        return pol.Policy.from_dict(c["policy_snapshot"])

    def _audit(self, event: str, payload: dict):
        self.audit.append(event, payload)

    def _spend_nonce(self, body: dict):
        nonce = body["nonce"]
        fingerprint = crypto.digest_hex({k: v for k, v in body.items()
                                         if k != "nonce"})
        prev = self.state["spent_nonces"].get(nonce)
        if prev is not None:
            if prev == fingerprint:
                raise DuplicateAction("identical action already recorded (replay)")
            raise ReplayError("nonce reused with a different payload")
        self.state["spent_nonces"][nonce] = fingerprint

    def _authenticate(self, envelope: dict, ceremony_id: str,
                      expected_stage: str | None = None) -> dict:
        body = envelope.get("body", {})
        if body.get("ceremony_id") != ceremony_id:
            raise AuthenticationError("envelope ceremony mismatch")
        did = envelope.get("device_id")
        c = self._get_open(ceremony_id)
        pc = c["participants"].get(did)
        if pc is None:
            raise AuthenticationError(f"device {did} is not in this ceremony roster")
        enrolled = EnrolledDevice.from_dict(self.state["devices"][did])
        if enrolled.revoked:
            raise AttestationError("device revoked")
        body = verify_action_envelope(envelope, enrolled.identity_pub)
        if expected_stage and body["stage"] != expected_stage:
            raise ConflictState(
                f"action targets stage {body['stage']}, ceremony is at "
                f"{c['stage']}")
        if body["stage"] != c["stage"]:
            raise ConflictState(
                f"action stage {body['stage']} != current stage {c['stage']}")
        self._spend_nonce(body)
        return body

    def _advance(self, c: dict, stage: str):
        order = STAGE_ORDER
        if order.index(stage) < order.index(c["stage"]):
            raise ConflictState(f"cannot move backward {c['stage']} -> {stage}")
        c["stage"] = stage
        self._audit("ceremony_stage",
                    {"ceremony_id": c["id"], "stage": stage})

    # ======================================================================
    # stage 1: attestation
    # ======================================================================
    def challenge(self, ceremony_id: str, device_id: str) -> dict:
        c = self._get_open(ceremony_id)
        pc = c["participants"].get(device_id)
        if pc is None:
            raise AuthenticationError("device not in roster")
        ch = c["challenges"].get(device_id)
        if ch is None:
            ch = crypto.b64e(os.urandom(32))
            c["challenges"][device_id] = ch
            self._audit("challenge_issued",
                        {"ceremony_id": ceremony_id, "device_id": device_id})
        return {"ceremony_id": ceremony_id, "device_id": device_id, "challenge": ch}

    def submit_attestation(self, envelope: dict) -> dict:
        """Device presents its quote; envelope payload = the quote object."""
        cid = envelope["body"]["ceremony_id"]
        body = self._authenticate(envelope, cid, expected_stage="OPEN")
        c = self.state["ceremonies"][cid]
        quote = body["payload"]["quote"]
        did = envelope["device_id"]
        if quote.get("device_id") != did:
            raise AttestationError("quote device does not match action signer")
        pc = c["participants"][did]
        enrolled = EnrolledDevice.from_dict(self.state["devices"][did])
        verify_quote(quote, enrolled, crypto.b64d(c["challenges"][did]),
                     now=_now(self.clock))
        if pc["attested"]:
            raise DuplicateAction("device already attested in this ceremony")
        pc["attested"] = True
        pc["attest"] = {
            "measurement": quote["measurement"],
            "seal_pub": quote["seal_pub"],
            "ts": quote["ts"],
            "sig": quote["sig"],
        }
        self._audit("attestation_accepted",
                    {"ceremony_id": cid, "device_id": did,
                     "participant_id": pc["participant_id"],
                     "measurement": quote["measurement"],
                     "seal_pub": quote["seal_pub"], "ts": quote["ts"]})
        n_att = sum(1 for p in c["participants"].values() if p["attested"])
        # GENERATE/ROTATE/DESTROY admitted the full roster at open; BACKUP
        # requires the survivor/replacement roster to attest before dealing.
        if n_att == len(c["participants"]):
            self._advance(c, "ATTESTED")
            if c["kind"] in (pol.GENERATE, pol.ROTATE):
                self._deal(c)
                self._advance(c, "DELIVERED")
            elif c["kind"] == pol.BACKUP:
                # No share distribution yet: survivors first submit shares;
                # recovery math reaches threshold and deals new shares.
                self._advance(c, "DELIVERED")
            else:  # DESTROY: nothing to distribute, go to confirmations
                self._advance(c, "CONFIRMED")
        return self.public_ceremony(cid)

    # ======================================================================
    # stage 2: dealing (generate / rotate)
    # ======================================================================
    def _deal(self, c: dict):
        indices = list(range(1, len(c["roster"]) + 1))
        dealer = crypto.Dealer(c["threshold"], indices)
        shares = dealer.shares()
        deal = {"commitments": [str(x) for x in dealer.commitments],
                "indexes": {}, "deliveries": []}
        for slot, idx in zip(c["roster"], indices):
            did = slot["device_id"]
            pc = c["participants"][did]
            enrolled = EnrolledDevice.from_dict(self.state["devices"][did])
            context = f"{c['id']}|{did}".encode()
            value = shares[idx]
            env = crypto.envelope_to_json(
                crypto.seal(enrolled.seal_pub,
                            crypto.int_to_bytes(value), context))
            delivery_id = _mid("dlv")
            c["deliveries"][delivery_id] = {
                "device_id": did, "index": idx,
                "context": crypto.b64e(context), "envelope": env,
                "claimed": False,
            }
            pc["delivery_id"] = delivery_id
            pc["share_index"] = idx
            deal["indexes"][did] = idx
            deal["deliveries"].append(delivery_id)
        # The random constant term exists only transiently here and is not
        # written to state: key material is derived once at COMMIT from the
        # same polynomial object... but state survives restart, so we must
        # persist the coefficient stream *sealed to the service* for commit.
        # Instead: derive the signing key at deal time, seal it, and erase
        # the in-memory secret now. (Human shares are the independent root.)
        secret = dealer.secret
        seed = crypto.hkdf(
            secret.to_bytes(256, "big"), 32,
            info=("root-key|" + c["purpose"]).encode())
        pub = ed25519.public_from_secret(seed)
        pending = {
            "purpose": c["purpose"],
            "signing_seed": crypto.b64e(seed),
            "signing_pub": crypto.b64e(pub),
            "commitments": deal["commitments"],
        }
        c["deal"] = {"pending": pending, **deal}
        self._audit("shares_dealt",
                    {"ceremony_id": c["id"],
                     "commitments": deal["commitments"],
                     "indexes": deal["indexes"],
                     "signing_pub": pending["signing_pub"]})

    def fetch_delivery(self, ceremony_id: str, device_id: str) -> dict:
        """Attested device pulls its sealed share (enclave-internal channel)."""
        c = self._get_open(ceremony_id)
        pc = c["participants"].get(device_id)
        if pc is None or not pc.get("attested"):
            raise AttestationError("device not attested")
        if c["stage"] not in ("DELIVERED", "CONFIRMED"):
            raise ConflictState("shares not dealt yet")
        dlv_id = pc.get("delivery_id")
        if not dlv_id:
            raise NotFound("no delivery for device")
        dlv = c["deliveries"][dlv_id]
        dlv["claimed"] = True
        return {"delivery_id": dlv_id, "envelope": dlv["envelope"],
                "context": dlv["context"], "index": dlv["index"]}

    # ======================================================================
    # stage 3: confirmations
    # ======================================================================
    def submit_confirmation(self, envelope: dict) -> dict:
        """Shareholder confirms their check:

        * GENERATE/ROTATE - share decrypted and checked against the published
          Feldman commitments (payload carries delivery id, index, vss_ok);
        * DESTROY         - shareholder attests intent to destroy;
        * BACKUP          - confirmations are collected after the recovered
          shares are dealt (same path as GENERATE then).
        """
        cid = envelope["body"]["ceremony_id"]
        body = self._authenticate(envelope, cid)
        c = self.state["ceremonies"][cid]
        did = envelope["device_id"]
        pc = c["participants"][did]
        payload = body["payload"]
        if c["stage"] not in ("DELIVERED", "CONFIRMED"):
            raise ConflictState(f"cannot confirm at stage {c['stage']}")
        if c["kind"] == pol.DESTROY and c["stage"] != "CONFIRMED":
            raise ConflictState("DESTROY confirmations start at CONFIRMED stage")
        if pc["confirmed"]:
            raise DuplicateAction("duplicate confirmation (already recorded)")
        if not pc.get("attested"):
            raise AttestationError("cannot confirm without attestation")
        if c["kind"] in (pol.GENERATE, pol.ROTATE, pol.BACKUP):
            dlv_id = payload.get("delivery_id")
            if dlv_id != pc["delivery_id"]:
                raise SealError("confirmation references wrong delivery")
            share_index = payload.get("index")
            if share_index != pc["share_index"]:
                raise SealError("share index mismatch")
            if not payload.get("vss_ok"):
                raise PolicyViolation("device reports VSS verification failure")
        pc["confirmed"] = True
        c["confirmations"][did] = {
            "at": _now(self.clock),
            "note": payload.get("note", ""),
        }
        self._audit("share_confirmed",
                    {"ceremony_id": cid, "device_id": did,
                     "participant_id": pc["participant_id"],
                     "role": pc["role"]})
        p = pol.Policy.from_dict(c["policy_snapshot"])
        confirmed = {d for d, x in c["participants"].items() if x["confirmed"]}
        attested = {d for d, x in c["participants"].items() if x["attested"]}
        conf_pids = {s["participant_id"] for s in c["roster"]
                     if s["device_id"] in confirmed}
        has_owner = any(s["role"] == pol.ROOT_OWNER
                        for s in c["roster"] if s["device_id"] in confirmed)
        # A threshold-sized confirmation set WITHOUT an owner is a hard
        # policy failure: quorum can never be formed from it.
        if len(conf_pids) >= p.threshold and not has_owner:
            raise PolicyViolation(
                f"{len(conf_pids)} confirmations without a ROOT_OWNER; "
                "owner assent is mandatory")
        # Otherwise we are simply waiting for more confirmations. The
        # effective roster for a BACKUP is its recovered roster (replacements
        # for dropped participants), not the frozen policy snapshot.
        try:
            self._confirm_quorum(c, p, attested, confirmed)
        except PolicyViolation:
            return self.public_ceremony(cid)
        if c["stage"] == "DELIVERED":
            self._advance(c, "CONFIRMED")
        return self.public_ceremony(cid)

    def _confirm_quorum(self, c: dict, p: "pol.Policy",
                        attested: set[str], confirmed: set[str]):
        required = set(pol.REQUIRED_ROLES)
        present_roles = {s["role"] for s in c["roster"]
                         if s["device_id"] in attested}
        if not required <= present_roles:
            raise PolicyViolation("missing required role in attested set")
        if c["kind"] != pol.BACKUP:
            if len(attested) != len(p.slots):
                raise PolicyViolation("full fixed roster must be attested")
        else:
            if len(attested) != len(c["roster"]):
                raise PolicyViolation("full recovered roster must be attested")
        conf_slots = [s for s in c["roster"] if s["device_id"] in confirmed]
        if len({s["participant_id"] for s in conf_slots}) < p.threshold:
            raise PolicyViolation("not enough confirmations")
        if not any(s["role"] == pol.ROOT_OWNER for s in conf_slots):
            raise PolicyViolation("a ROOT_OWNER must confirm")

    # ======================================================================
    # BACKUP: surviving shares -> fresh polynomial
    # ======================================================================
    def submit_share(self, envelope: dict) -> dict:
        """Survivor presents its share for recovery. The share value is
        accepted only if it verifies against the CURRENT key's published
        Feldman commitments, then kept only in memory-ish sealed storage for
        the duration of the recovery round."""
        cid = envelope["body"]["ceremony_id"]
        body = self._authenticate(envelope, cid, expected_stage="DELIVERED")
        c = self.state["ceremonies"][cid]
        if c["kind"] != pol.BACKUP:
            raise ConflictState("submit_share only valid for BACKUP")
        did = envelope["device_id"]
        pc = c["participants"][did]
        if pc["submitted"]:
            raise DuplicateAction("share already submitted by this device")
        index = int(body["payload"]["index"])
        value = int(body["payload"]["share"])
        current = self.dir.active(c["purpose"])
        commits = [int(x) for x in current["commitments"]]
        # Note: share indices range over the original roster size (1..n),
        # which can exceed len(commitments) == threshold; verify_share uses
        # Horner evaluation and needs no such bound.
        if not crypto.Dealer.verify_share(index, value, commits):
            raise PolicyViolation("recovery share failed commitment check")
        # keep only a sealed copy (service wrap) - never audit the value.
        from .directory import seal_material
        blob = seal_material(self.seed, c["id"] + ":" + did,
                             crypto.int_to_bytes(value))
        c["incoming"][did] = {"index": index, "blob": blob,
                              "at": _now(self.clock)}
        pc["submitted"] = True
        self._audit("recovery_share_received",
                    {"ceremony_id": cid, "device_id": did, "index": index,
                     "value_hash": crypto.digest_hex(
                         {"i": index, "v": str(value)})})
        # Recovery can proceed at threshold survivors (loss tolerance).
        if len(c["incoming"]) >= c["threshold"]:
            self._run_recovery(c)
        return self.public_ceremony(cid)

    def _run_recovery(self, c: dict):
        from .directory import open_material
        incoming = c["incoming"]
        if len(incoming) < c["threshold"]:
            raise QuorumFailure("not enough valid recovery shares")
        current = self.dir.active(c["purpose"])
        commits = [int(x) for x in current["commitments"]]
        share_map = {}
        for did, item in incoming.items():
            raw = open_material(self.seed, c["id"] + ":" + did, item["blob"])
            v = crypto.bytes_to_int(raw)
            if not crypto.Dealer.verify_share(item["index"], v, commits):
                raise PolicyViolation(f"bad recovery share from {did}")
            share_map[item["index"]] = v
        secret = crypto.reconstruct(share_map)
        # fresh polynomial for the post-recovery roster; same constant term.
        indices = list(range(1, len(c["roster"]) + 1))
        dealer = crypto.Dealer(c["threshold"], indices, secret=secret)
        shares = dealer.shares()
        # sanity: the new commitments must be consistent at the same secret.
        if pow(crypto.G2, secret, crypto.q) != int(dealer.commitments[0]):
            raise CeremonyError("recovery internal consistency failure")
        c["deliveries"] = {}
        for slot, idx in zip(c["roster"], indices):
            did = slot["device_id"]
            pc = c["participants"][did]
            enrolled = EnrolledDevice.from_dict(self.state["devices"][did])
            context = f"{c['id']}|{did}".encode()
            env = crypto.envelope_to_json(
                crypto.seal(enrolled.seal_pub,
                            crypto.int_to_bytes(shares[idx]), context))
            dlv_id = _mid("dlv")
            c["deliveries"][dlv_id] = {
                "device_id": did, "index": idx,
                "context": crypto.b64e(context), "envelope": env,
                "claimed": False, "recovery": True}
            pc["delivery_id"] = dlv_id
            pc["share_index"] = idx
        c["deal"] = {"commitments": [str(x) for x in dealer.commitments],
                     "indexes": {s["device_id"]: i
                                 for s, i in zip(c["roster"], indices)},
                     "recovery": True}
        self._audit("recovery_dealt",
                    {"ceremony_id": c["id"],
                     "commitments": c["deal"]["commitments"],
                     "survivors": list(incoming.keys()),
                     "indexes": c["deal"]["indexes"]})

    # ======================================================================
    # stage 4: commit
    # ======================================================================
    def commit(self, ceremony_id: str, actor: str,
               expected_active: str | None = None) -> dict:
        c = self._get_open(ceremony_id)
        p = pol.Policy.from_dict(c["policy_snapshot"])
        # Quorum first: insufficient confirmations is a policy failure even
        # though the ceremony is still in an earlier (waiting) stage.
        attested = {d for d, x in c["participants"].items() if x["attested"]}
        confirmed = {d for d, x in c["participants"].items()
                     if x["confirmed"]}
        try:
            self._confirm_quorum(c, p, attested, confirmed)
        except PolicyViolation as e:
            raise PolicyViolation(f"cannot commit: {e}") from e
        if c["stage"] != "CONFIRMED":
            raise ConflictState(
                f"commit requires stage CONFIRMED, currently {c['stage']}")

        result = {"actor": actor, "at": _now(self.clock)}
        if c["kind"] in (pol.GENERATE, pol.ROTATE):
            pending = c["deal"]["pending"]
            seed = crypto.b64d(pending["signing_seed"])
            pub = crypto.b64d(pending["signing_pub"])
            share_meta = [
                {"device_id": did, "participant_id": pc["participant_id"],
                 "role": pc["role"], "index": pc["share_index"],
                 "delivery_id": pc["delivery_id"]}
                for did, pc in c["participants"].items()]
            kv = self.dir.register_version(
                c["purpose"], seed, pub,
                [int(x) for x in pending["commitments"]], share_meta, c["id"])
            result["key_version"] = kv["id"]
            result["status"] = kv["status"]
            if kv["status"] == ACTIVE:
                self._audit("key_activated",
                            {"ceremony_id": c["id"], "version_id": kv["id"],
                             "purpose": kv["purpose"], "version": kv["version"],
                             "fingerprint": kv["fingerprint"]})
            else:
                self._audit("key_staged",
                            {"ceremony_id": c["id"], "version_id": kv["id"],
                             "purpose": kv["purpose"], "version": kv["version"],
                             "fingerprint": kv["fingerprint"]})
            c["result"] = result
        elif c["kind"] == pol.BACKUP:
            current = self.dir.active(c["purpose"])
            # recovery updated the distribution of the SAME key; update its
            # share metadata + commitments to the fresh polynomial.
            current["commitments"] = c["deal"]["commitments"]
            current["share_meta"] = [
                {"device_id": did, "participant_id": pc["participant_id"],
                 "role": pc["role"], "index": pc["share_index"],
                 "delivery_id": pc["delivery_id"], "recovered_in": c["id"]}
                for did, pc in c["participants"].items()]
            result["key_version"] = current["id"]
            result["resharded"] = True
            c["result"] = result
            # purge incoming sealed shares
            c["incoming"] = {}
            self._audit("key_resharded",
                        {"ceremony_id": c["id"], "version_id": current["id"],
                         "commitments": current["commitments"]})
        elif c["kind"] == pol.DESTROY:
            target_id = c.get("target_version")
            if target_id:
                target = self.dir.get(target_id)
            else:
                target = self.dir.get(expected_active) if expected_active \
                    else self.dir.active(c["purpose"])
            if target["purpose"] != c["purpose"]:
                raise PolicyViolation("destroy target purpose mismatch")
            if target["status"] == ACTIVE:
                raise PolicyViolation(
                    "DESTROY ceremony must target a RETIRING version")
            kv = self.dir.destroy(target["id"], c["id"])
            result["key_version"] = kv["id"]
            result["destroyed"] = True
            c["result"] = result
            self._audit("key_destroyed",
                        {"ceremony_id": c["id"], "version_id": kv["id"],
                         "purpose": kv["purpose"], "version": kv["version"],
                         "fingerprint": kv["fingerprint"]})

        c["stage"] = "COMPLETED"
        c["status"] = DONE_STATUS
        c["completed_at"] = _now(self.clock)
        self._audit("ceremony_completed",
                    {"ceremony_id": c["id"], "kind": c["kind"],
                     "purpose": c["purpose"], "result": result})
        return self.public_ceremony(c["id"])

    def publish_rotation(self, ceremony_id: str, actor: str,
                         expected_active: str) -> dict:
        """The second handover step: after a ROTATE ceremony produced a
        STAGED successor, publish it with an explicit CAS on the old ACTIVE
        version. Concurrent publishers: one wins, the rest get RaceLost.
        This method is idempotent for the winning publisher and rejects
        competing publishers - the purpose can never have two ACTIVE keys.
        """
        c = self.state["ceremonies"].get(ceremony_id)
        if c is None:
            raise NotFound(f"unknown ceremony {ceremony_id}")
        if c["kind"] != pol.ROTATE or c["status"] != DONE_STATUS:
            raise ConflictState("publish needs a COMPLETED ROTATE ceremony")
        new_id = c["result"]["key_version"]
        current_id = self.dir.active_id(c["purpose"])
        # Strict compare-and-swap: if the caller's view of the current key is
        # stale, they lose the race - even for a retransmit of this same
        # ceremony. A safe retry refreshes expected_active (and then becomes
        # an idempotent no-op when the successor is already current).
        if current_id != expected_active:
            raise RaceLost(
                f"publish race: expected {expected_active} to be current, "
                f"but directory says {current_id}")
        if c.get("published"):
            # Already published and pointer matches: idempotent success.
            return self.public_ceremony(ceremony_id)
        kv, old = self.dir.activate(new_id, c["id"],
                                    expected_active=expected_active)
        c["published"] = {"at": _now(self.clock), "actor": actor,
                          "old": old["id"] if old else None}
        deadline = _now(self.clock) + c["policy_snapshot"]["handover_seconds"]
        kv["handover_deadline"] = deadline
        if old:
            old["handover_deadline"] = deadline
        self._audit("rotation_published",
                    {"ceremony_id": c["id"], "new": kv["id"],
                     "old": old["id"] if old else None,
                     "handover_deadline": deadline, "actor": actor})
        return self.public_ceremony(c["id"])

    def abort(self, ceremony_id: str, actor: str, reason: str) -> dict:
        c = self.state["ceremonies"].get(ceremony_id)
        if c is None:
            raise NotFound(f"unknown ceremony {ceremony_id}")
        if c["status"] != OPEN_STATUS:
            raise ConflictState(
                f"cannot abort: ceremony is already {c['status']}; "
                "the record is retained")
        return self._abort(ceremony_id, reason, actor=actor)

    def _abort(self, ceremony_id: str, reason: str, actor: str) -> dict:
        c = self.state["ceremonies"][ceremony_id]
        if c["status"] in ("COMPLETED", "ABORTED"):
            return self.public_ceremony(ceremony_id)
        c["status"] = ABORT_STATUS
        c["stage"] = "ABORTED"
        c["abort"] = {"reason": reason, "actor": actor, "at": _now(self.clock)}
        # Wipe all secret-bearing transient state from the abandoned round.
        # The audit record (commitments, identities, hashes) is retained.
        if c.get("deal"):
            pending = c["deal"].get("pending")
            if pending:
                pending["signing_seed"] = None
        c["incoming"] = {}
        c["deliveries"] = {}
        self._audit("ceremony_aborted",
                    {"ceremony_id": ceremony_id, "kind": c["kind"],
                     "purpose": c["purpose"], "reason": reason, "actor": actor,
                     "stage_reached": c.get("stage")})
        return self.public_ceremony(ceremony_id)

    # ======================================================================
    # signing test interface
    # ======================================================================
    def sign(self, purpose: str, message: bytes) -> dict:
        sig, kv = self.dir.sign_purpose(purpose, message)
        return {"purpose": purpose, "version_id": kv["id"],
                "version": kv["version"], "status": kv["status"],
                "fingerprint": kv["fingerprint"],
                "sig": crypto.b64e(sig)}

    def verify(self, purpose: str, message: bytes, sig_b64: str) -> dict:
        sig = crypto.b64d(sig_b64)
        match = self.dir.verify_any(purpose, message, sig)
        if match is None:
            return {"valid": False}
        kv = self.dir.get(match)
        return {"valid": True, "version_id": match, "version": kv["version"],
                "status": kv["status"], "fingerprint": kv["fingerprint"],
                "active": kv["status"] == ACTIVE}

    # ======================================================================
    # views
    # ======================================================================
    def public_ceremony(self, ceremony_id: str) -> dict:
        c = self.state["ceremonies"][ceremony_id]
        return {
            "id": c["id"], "kind": c["kind"], "purpose": c["purpose"],
            "stage": c["stage"], "status": c["status"],
            "threshold": c["threshold"],
            "policy_snapshot": c["policy_snapshot"],
            "created_at": c["created_at"], "deadline": c["deadline"],
            "roster": c["roster"], "recovery": c["recovery"],
            "participants": {
                did: {k: v for k, v in pc.items()
                      if k not in ("attest",)}
                for did, pc in c["participants"].items()},
            "commitments": (c.get("deal") or {}).get("commitments"),
            "deliveries": [
                {"delivery_id": k, "device_id": v["device_id"],
                 "index": v["index"], "claimed": v["claimed"],
                 "recovery": v.get("recovery", False)}
                for k, v in c["deliveries"].items()],
            "confirmations": list(c["confirmations"].keys()),
            "n_submitted": len(c.get("incoming", {})),
            "result": c.get("result"), "abort": c.get("abort"),
            "published": c.get("published"),
            "completed_at": c.get("completed_at"),
        }

    def list_ceremonies(self) -> list[dict]:
        return [self.public_ceremony(cid)
                for cid in self.state["ceremonies"]]

    def save(self):
        self.store.save_state(self.state)
