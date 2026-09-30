"""Key version directory: activation, handover coexistence, signing.

Version status machine (per purpose):

    STAGED ──activate──> ACTIVE ──(a newer version activates)──> RETIRING
      │                      │                                         │
   abort                  destroy                                  destroy
      │                      │                                         │
      v                      v                                         v
   ABORTED              DESTROYED <───────────────────────────────────┘

Invariants enforced here:
  * exactly one ACTIVE version per purpose at all times (compare-and-swap
    under the store lock - concurrent rotation publishes cannot produce two
    current keys);
  * signers may only use the ACTIVE version;
  * verifiers continue to recognize STAGED/ACTIVE/RETIRING/DESTROYED
    historical versions (public verification material is retained even after
    destruction; only the private signing material is zeroized);
  * an ACTIVE and the new STAGED key coexist deliberately during the
    handover window.
"""

from __future__ import annotations

import os
import time

from . import crypto, ed25519
from .errors import ConflictState, NotFound, PolicyViolation, RaceLost

STAGED = "STAGED"
ACTIVE = "ACTIVE"
RETIRING = "RETIRING"
DESTROYED = "DESTROYED"
ABORTED = "ABORTED"

VERIFIABLE_STATUSES = (STAGED, ACTIVE, RETIRING, DESTROYED)
_SIGNABLE_STATUSES = (ACTIVE,)


def now_ts(clock) -> float:
    return float(clock())


def _fingerprint(purpose: str, version: int, pub: bytes) -> str:
    return crypto.digest_hex({
        "purpose": purpose, "version": version, "signing_pub": crypto.b64e(pub)})[:16]


def wrap_key_from_service_seed(service_seed: bytes, version_id: str) -> bytes:
    """Per-version material-encryption key derived from the service's
    long-lived secret (in production this is the HSM master-wrap key; the
    human threshold shares remain the independent social control)."""
    return crypto.hkdf(service_seed, 32, info=("wrap|" + version_id).encode())


def seal_material(service_seed: bytes, version_id: str, seed: bytes) -> dict:
    """Symmetric AEAD wrap of signing material under a per-version key
    derived from the service's long-lived secret (production: HSM LMK).
    The human threshold shares remain the independent social control."""
    import hashlib
    import hmac as _hmac

    wk = wrap_key_from_service_seed(service_seed, version_id)
    nonce = os.urandom(16)
    stream = b""
    ctr = 0
    while len(stream) < len(seed):
        stream += hashlib.sha256(wk + nonce + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    ct = bytes(a ^ b for a, b in zip(seed, stream))
    tag = _hmac.new(wk, nonce + ct + version_id.encode(), hashlib.sha256).digest()
    return {"nonce": crypto.b64e(nonce), "ct": crypto.b64e(ct),
            "tag": crypto.b64e(tag), "alg": "kc-aead-v1"}


def open_material(service_seed: bytes, version_id: str, blob: dict) -> bytes:
    import hashlib
    import hmac as _hmac

    wk = wrap_key_from_service_seed(service_seed, version_id)
    nonce, ct, tag = crypto.b64d(blob["nonce"]), crypto.b64d(blob["ct"]), crypto.b64d(blob["tag"])
    expect = _hmac.new(wk, nonce + ct + version_id.encode(), hashlib.sha256).digest()
    if not _hmac.compare_digest(expect, tag):
        raise ConflictState("wrap tag invalid for " + version_id)
    stream = b""
    ctr = 0
    while len(stream) < len(ct):
        stream += hashlib.sha256(wk + nonce + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    return bytes(a ^ b for a, b in zip(ct, stream))


class KeyDirectory:
    def __init__(self, state: dict, service_seed: bytes, clock=time.time):
        self.s = state
        self.seed = service_seed
        self.clock = clock

    # ---- queries ---------------------------------------------------------
    def get(self, version_id: str) -> dict:
        if version_id not in self.s["keys"]:
            raise NotFound(f"unknown key version {version_id}")
        return self.s["keys"][version_id]

    def active_id(self, purpose: str) -> str | None:
        vid = self.s["purposes"].get(purpose)
        if vid and self.get(vid)["status"] == ACTIVE:
            return vid
        return None

    def active(self, purpose: str) -> dict | None:
        vid = self.active_id(purpose)
        return self.get(vid) if vid else None

    def versions_for_purpose(self, purpose: str) -> list[dict]:
        out = [k for k in self.s["keys"].values() if k["purpose"] == purpose]
        return sorted(out, key=lambda k: k["version"])

    def has_any_non_destroyed(self, purpose: str) -> bool:
        return any(k["purpose"] == purpose and k["status"] != DESTROYED
                   for k in self.s["keys"].values())

    # ---- lifecycle -------------------------------------------------------
    def register_version(self, purpose: str, signing_seed: bytes,
                         signing_pub: bytes, commitments: list[int],
                         share_meta: list[dict], ceremony_id: str) -> dict:
        """Materialize a version produced by a completed GENERATE/ROTATE.
        It becomes ACTIVE if and only if nothing is currently active for the
        purpose; otherwise it is staged for the handover window."""
        version = len(self.versions_for_purpose(purpose)) + 1
        vid = "kv_" + crypto.b64e(
            crypto.digest({"purpose": purpose, "version": version,
                           "ceremony": ceremony_id,
                           "r": crypto.b64e(os.urandom(8))}))[:22]
        status = ACTIVE if self.active_id(purpose) is None else STAGED
        kv = {
            "id": vid,
            "purpose": purpose,
            "version": version,
            "status": status,
            "signing_pub": crypto.b64e(signing_pub),
            "fingerprint": _fingerprint(purpose, version, signing_pub),
            "commitments": [str(c) for c in commitments],
            "share_meta": share_meta,
            "source_ceremony": ceremony_id,
            "created_at": now_ts(self.clock),
            "activated_at": now_ts(self.clock) if status == ACTIVE else None,
            "retired_at": None,
            "destroyed_at": None,
            "destroy_ceremony": None,
            "handover_deadline": None,
        }
        self.s["keys"][vid] = kv
        self.s["wraps"][vid] = seal_material(self.seed, vid, signing_seed)
        if status == ACTIVE:
            self.s["purposes"][purpose] = vid
        return kv

    def activate(self, version_id: str, ceremony_id: str,
                 expected_active: str | None = None) -> tuple[dict, dict | None]:
        """Compare-and-swap activation.

        expected_active pins what the publisher believes is current; a
        mismatch (lost race) raises RaceLost. Exactly one ACTIVE per purpose
        is maintained: the previous ACTIVE becomes RETIRING and the handover
        window starts, during which both keys coexist for verifiers while
        only the new one signs.
        """
        kv = self.get(version_id)
        purpose = kv["purpose"]
        cur_id = self.s["purposes"].get(purpose)
        if expected_active is not None and cur_id != expected_active:
            raise RaceLost(
                f"publish race: expected {expected_active} to be current, "
                f"but directory says {cur_id}")
        if cur_id == version_id:
            return kv, None  # idempotent re-activation
        if kv["status"] not in (STAGED,):
            raise ConflictState(
                f"cannot activate {version_id}: status {kv['status']}")
        old = self.get(cur_id) if cur_id else None
        # Defensive single-current-key assertion (should be unreachable).
        actives = [k["id"] for k in self.s["keys"].values()
                   if k["purpose"] == purpose and k["status"] == ACTIVE]
        if len(actives) > 1:
            raise RaceLost(f"invariant violation: {actives}")
        if old is not None:
            if old["status"] != ACTIVE:
                raise RaceLost(f"current key {cur_id} not ACTIVE ({old['status']})")
            old["status"] = RETIRING
            old["retired_at"] = now_ts(self.clock)
        kv["status"] = ACTIVE
        kv["activated_at"] = now_ts(self.clock)
        kv["handover_deadline"] = None
        self.s["purposes"][purpose] = version_id
        return kv, old

    def destroy(self, version_id: str, ceremony_id: str) -> dict:
        """Zeroize private material; retain public key for historical verify."""
        kv = self.get(version_id)
        if kv["status"] == DESTROYED:
            return kv
        if kv["status"] == ACTIVE:
            raise PolicyViolation(
                "cannot destroy the ACTIVE key: rotate a successor first")
        # Destroy the wrap. Keep the public key + fingerprint + commitments.
        self.s["wraps"].pop(version_id, None)
        kv["status"] = DESTROYED
        kv["destroyed_at"] = now_ts(self.clock)
        kv["destroy_ceremony"] = ceremony_id
        return kv

    def abort_staged(self, version_id: str):
        kv = self.get(version_id)
        if kv["status"] != STAGED:
            raise ConflictState("only STAGED versions can be aborted")
        self.s["wraps"].pop(version_id, None)
        kv["status"] = ABORTED

    # ---- signing / verification -----------------------------------------
    def _seed(self, version_id: str) -> bytes:
        blob = self.s["wraps"].get(version_id)
        if blob is None:
            raise ConflictState("private material unavailable for " + version_id)
        return open_material(self.seed, version_id, blob)

    def signer_sign(self, version_id: str, message: bytes) -> bytes:
        kv = self.get(version_id)
        if kv["status"] not in _SIGNABLE_STATUSES:
            raise ConflictState(
                f"signers may only use ACTIVE versions "
                f"({version_id} is {kv['status']})")
        seed = self._seed(version_id)
        return ed25519.sign(seed, message)

    def sign_purpose(self, purpose: str, message: bytes) -> tuple[bytes, dict]:
        kv = self.active(purpose)
        if kv is None:
            raise NotFound(f"no ACTIVE key for purpose {purpose}")
        return self.signer_sign(kv["id"], message), kv

    def verify_version(self, version_id: str, message: bytes, sig: bytes) -> bool:
        kv = self.get(version_id)
        if kv["status"] not in VERIFIABLE_STATUSES:
            return False
        return ed25519.verify(crypto.b64d(kv["signing_pub"]), message, sig)

    def verify_any(self, purpose: str, message: bytes, sig: bytes) -> str | None:
        """Verifier path: accept signatures under *any* recognized historical
        version of the purpose. Returns the matching version id or None."""
        for kv in self.versions_for_purpose(purpose):
            if kv["status"] in VERIFIABLE_STATUSES:
                if ed25519.verify(crypto.b64d(kv["signing_pub"]), message, sig):
                    return kv["id"]
        return None
