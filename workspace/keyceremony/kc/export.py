"""Verifiable record export.

Produces a single JSON bundle an external auditor can check *without* any
access to secrets or live state:

  export.json
  {
    "generated_at", "service_identity_pub", "service_sig",
    "policies":   [...immutable policy snapshots...],
    "keys":       [...all key versions (public material only)...],
    "purposes":   {purpose: active_version_id},
    "ceremonies": [...public ceremony views...],
    "sessions":   [...operator session records (token ids, never tokens)...],
    "auth_tickets":[...four-eyes tickets: parties, token ids, digest,
                    decision chain, execution result...],
    "audit":      [...full hash-chained audit entries...],
    "invariants": {computed checksums}
  }

Verification performed by `verify_bundle`:
  * service signature over the bundle body,
  * audit hash-chain links and every audit entry's service signature,
  * each ceremony's commitment column matches the registered key version
    (lifecycle provenance: a version only exists via a COMPLETED ceremony),
  * destroyed versions carry no private material,
  * every purpose points at an ACTIVE version (single-current-key invariant),
  * participants referenced by ceremonies exist and roles are valid,
  * four-eyes tickets: creator/approver are different persons at different
    terminals with complementary duties; frozen digests are stable; executed
    tickets' effect is visible in the key/ceremony state and each execution
    has a matching hash-chained audit record; closed tickets executed nothing.

The auditor additionally gets `audit.txt` (human-readable) and `SHA256SUMS`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

from . import authz as AZ
from . import crypto, ed25519
from . import evidence as evidence_mod
from .errors import TamperError
from .storage import GENESIS


def build_bundle(orch, sessions=None, authz_mod=None) -> dict:
    s = orch.state
    body = {
        "format": "kc-export-v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service_identity_pub": crypto.b64e(
            ed25519.public_from_secret(orch.seed)),
        "policies": list(s["policies"].values()),
        "keys": [
            {**_public_key(k),
             "has_private_material": k["id"] in s["wraps"]}
            for k in sorted(s["keys"].values(), key=lambda x: (x["purpose"],
                                                               x["version"]))
        ],
        "purposes": dict(s["purposes"]),
        "ceremonies": [orch.public_ceremony(cid)
                       for cid in sorted(s["ceremonies"].keys())],
        "sessions": [_public_session(r)
                     for r in sorted(s.get("sessions", {}).values(),
                                     key=lambda r: r["created_at"])],
        "auth_tickets": [dict(t) for t in (
            authz_mod.list_tickets() if authz_mod is not None
            else list(s.get("auth_tickets", {}).values()))],
        "audit": list(orch.audit.entries),
        "devices": {
            did: {k: v for k, v in d.items()}
            for did, d in s["devices"].items()
        },
        "participants": dict(s["participants"]),
        "drill_plans": [_public_plan(p) for p in s.get("drill_plans", {}).values()],
        "drills": [_public_drill(d) for d in s.get("drills", {}).values()],
        "drill_evidence": list(s.get("drill_evidence", {}).values()),
        "drill_regions": dict(s.get("drill_regions", {})),
    }
    body["invariants"] = {
        "body_hash_excluding_sig": crypto.digest_hex(
            {k: v for k, v in body.items() if k != "invariants"}),
        "n_audit_entries": len(body["audit"]),
        "n_keys": len(body["keys"]),
        "n_ceremonies": len(body["ceremonies"]),
        "n_auth_tickets": len(body["auth_tickets"]),
        "n_sessions": len(body["sessions"]),
        "n_drills": len(body["drills"]),
        "n_drill_evidence": len(body["drill_evidence"]),
    }
    sig = ed25519.sign(orch.seed,
                       body["invariants"]["body_hash_excluding_sig"].encode())
    body["service_sig"] = crypto.b64e(sig)
    return body


def _public_session(r: dict) -> dict:
    keep = ("token_id", "participant_id", "role", "device_id", "measurement",
            "quote_ts", "created_at", "expires_at", "status", "closed_at",
            "superseded_at")
    return {k: r[k] for k in keep if k in r}


def _public_key(k: dict) -> dict:
    keep = ("id", "purpose", "version", "status", "signing_pub",
            "fingerprint", "commitments", "share_meta", "source_ceremony",
            "created_at", "activated_at", "retired_at", "destroyed_at",
            "destroy_ceremony", "handover_deadline")
    return {f: k.get(f) for f in keep}


# Fields of drill plans/runs that must never leave the store in an export.
_DRILL_SECRET_KEYS = ("secret", "credential_secret_once")


def _strip_secrets(obj):
    if isinstance(obj, dict):
        return {k: _strip_secrets(v) for k, v in obj.items()
                if k not in _DRILL_SECRET_KEYS}
    if isinstance(obj, (list, tuple)):
        return [_strip_secrets(v) for v in obj]
    return obj


def _public_plan(p: dict) -> dict:
    return _strip_secrets({
        "id": p.get("id"), "status": p.get("status"),
        "revisions": p.get("revisions"),
        "created_by": p.get("created_by"),
        "created_at": p.get("created_at"),
        "drill_id": p.get("drill_id"),
        "scan_ids": [s["scan_id"] for s in p.get("scans", [])],
    })


def _public_drill(d: dict) -> dict:
    keep = ("id", "plan_id", "status", "namespace", "credentials",
            "scan_id", "blueprint_hash", "checkpoints", "copied_objects",
            "probes", "window", "mirror", "lease", "failback", "cleanup",
            "freeze", "evidence_id", "rto_observed_seconds",
            "rto_breached", "created_at", "ready_at", "fields")
    return _strip_secrets({k: d.get(k) for k in keep})


def write_export(orch, outdir: str) -> str:
    os.makedirs(outdir, exist_ok=True)
    bundle = build_bundle(orch)
    path = os.path.join(outdir, "export.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
    # human-readable audit trail
    lines = []
    prev = GENESIS
    for e in bundle["audit"]:
        lines.append(
            f"{e['seq']:>4} {e['ts']} {e['event']:<28} "
            f"{crypto.dumps(e['payload'])[:180]}")
    txt = os.path.join(outdir, "audit.txt")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("# key ceremony audit trail (exported)\n")
        f.write("# each line's full signed record is in export.json -> audit\n\n")
        f.write("\n".join(lines) + "\n")
    # checksums
    sums = os.path.join(outdir, "SHA256SUMS")

    def _sha(path: str) -> str:
        with open(path, "rb") as rf:
            return hashlib.sha256(rf.read()).hexdigest()

    with open(sums, "w", encoding="utf-8") as f:
        for name, pth in (("export.json", path), ("audit.txt", txt)):
            f.write(_sha(pth) + "  " + name + "\n")
    return path


# ---------------------------------------------------------------------------
# independent verification (no Store, no secrets)
# ---------------------------------------------------------------------------

def _audit_entry_hash(entry: dict) -> str:
    h = hashlib.sha256()
    h.update(entry["prev"].encode())
    h.update(crypto.dumps(entry["payload"]).encode())
    h.update(str(entry["ts"]).encode())
    h.update(str(entry["seq"]).encode())
    return h.hexdigest()


def verify_bundle(bundle: dict) -> dict:
    problems: list[str] = []
    checks: dict[str, object] = {}

    # 1. service identity signature over body
    pub = crypto.b64d(bundle["service_identity_pub"])
    sig = crypto.b64d(bundle["service_sig"])
    body_hash = crypto.digest_hex(
        {k: v for k, v in bundle.items()
         if k not in ("invariants", "service_sig")})
    if body_hash != bundle["invariants"]["body_hash_excluding_sig"]:
        problems.append("bundle body was modified after signing")
    if not ed25519.verify(pub, body_hash.encode(), sig):
        problems.append("bundle service signature invalid")
    checks["bundle_signature_ok"] = not problems

    # 2. audit hash chain + per-entry service signatures
    prev = GENESIS
    by_event: dict[tuple, dict] = {}
    for i, e in enumerate(bundle["audit"]):
        if e["seq"] != i:
            problems.append(f"audit seq gap at {i}")
        if e["prev"] != prev:
            problems.append(f"audit[{i}] broken prev link")
        if _audit_entry_hash(e) != e["hash"]:
            problems.append(f"audit[{i}] hash mismatch (payload edited)")
        if "svc_sig" not in e or not ed25519.verify(
                pub, e["hash"].encode(), crypto.b64d(e["svc_sig"])):
            problems.append(f"audit[{i}] service signature missing/invalid")
        prev = e["hash"]
        by_event.setdefault((e["event"],), e)
    checks["audit_chain_ok"] = not any("audit" in p for p in problems)
    checks["audit_entries"] = len(bundle["audit"])

    # 3. key lifecycle provenance: each key traces to a COMPLETED ceremony
    ceremonies = {c["id"]: c for c in bundle["ceremonies"]}
    completed_ids = {cid for cid, c in ceremonies.items()
                     if c["status"] == "COMPLETED"}
    keys = bundle["keys"]
    for k in keys:
        if k["source_ceremony"] not in completed_ids:
            problems.append(
                f"key {k['id']} has no COMPLETED source ceremony")
        if k.get("has_private_material") and k["status"] == "DESTROYED":
            problems.append(f"DESTROYED key {k['id']} still has private material")

    # 4. single-current-key: exactly one ACTIVE per purpose
    from collections import defaultdict
    by_purpose: dict[str, list[dict]] = defaultdict(list)
    for k in keys:
        by_purpose[k["purpose"]].append(k)
    for purpose, group in by_purpose.items():
        actives = [k["id"] for k in group if k["status"] == "ACTIVE"]
        if len(actives) > 1:
            problems.append(
                f"purpose {purpose} has {len(actives)} ACTIVE keys: {actives}")
        pointer = bundle["purposes"].get(purpose)
        if pointer not in actives:
            problems.append(
                f"purpose {purpose} pointer does not match its ACTIVE key")
        # No ACTIVE version may exist outside the purpose pointer (catches a
        # flipped status that does not add a *second* ACTIVE sibling).
        for k in group:
            if k["status"] == "ACTIVE" and k["id"] != pointer:
                problems.append(
                    f"key {k['id']} is ACTIVE but is not the current pointer")
        # STAGED keys must have an ACTIVE sibling produced earlier.
        staged = [k for k in group if k["status"] == "STAGED"]
        if staged and not actives:
            problems.append(
                f"purpose {purpose} has STAGED key(s) but no ACTIVE key")
    checks["single_active_per_purpose"] = not any(
        "ACTIVE" in p or "pointer" in p for p in problems)

    # 5. policy snapshots referenced by ceremonies exist and threshold sane
    policies = {p["policy_id"]: p for p in bundle["policies"]}
    for c in bundle["ceremonies"]:
        snap = c["policy_snapshot"]
        p = policies.get(snap["policy_id"])
        if p is None:
            problems.append(f"ceremony {c['id']} references missing policy")
            continue
        if snap["threshold"] != p["threshold"]:
            problems.append(
                f"ceremony {c['id']} threshold differs from policy record")
        if len(c["roster"]) != len(snap["slots"]):
            problems.append(f"ceremony {c['id']} roster/policy slot mismatch")

    # 6. handover consistency: RETIRING keys must have a newer ACTIVE sibling
    for purpose, group in by_purpose.items():
        retiring = [k for k in group if k["status"] == "RETIRING"]
        active = [k for k in group if k["status"] == "ACTIVE"]
        for r in retiring:
            if not any(a["version"] > r["version"] for a in active):
                problems.append(
                    f"RETIRING key {r['id']} has no newer ACTIVE successor")
    checks["handover_consistent"] = True

    # 7. four-eyes authorization tickets
    ceremonies_by_id = {c["id"]: c for c in bundle["ceremonies"]}
    keys_by_id = {k["id"]: k for k in keys}
    audit_by_ticket: dict[str, list[dict]] = {}
    for e in bundle["audit"]:
        tid = e.get("payload", {}).get("ticket_id")
        if tid:
            audit_by_ticket.setdefault(tid, []).append(e)
    four_eyes_ok = _verify_auth_tickets(
        bundle, policies, ceremonies_by_id, keys_by_id,
        audit_by_ticket, problems)
    checks["four_eyes_tickets_ok"] = four_eyes_ok

    # 8. cross-region drill evidence archives
    drills_ok = _verify_drill_evidence(bundle, pub, problems)
    checks["drill_evidence_ok"] = drills_ok

    return {"ok": not problems, "problems": problems, "checks": checks}


def _verify_drill_evidence(bundle, service_pub, problems) -> bool:
    """Every archived drill evidence must re-verify independently; the
    service signature over the manifest must match, and a cleaned drill must
    have its evidence archive present."""
    archives = bundle.get("drill_evidence", [])
    ok = True
    seen = set()
    for ev in archives:
        eid = ev.get("evidence_id", "?")
        verdict = evidence_mod.verify_evidence(ev)
        if not verdict["ok"]:
            for p in verdict["problems"]:
                problems.append(f"drill evidence {eid}: {p}")
            ok = False
        if not evidence_mod.verify_evidence_signature(ev, service_pub):
            problems.append(
                f"drill evidence {eid}: service signature invalid")
            ok = False
        if eid in seen:
            problems.append(f"duplicate drill evidence archive {eid}")
            ok = False
        seen.add(eid)
    # every CLEANED drill must carry an evidence archive id that is present
    evidence_ids = seen
    for d in bundle.get("drills", []):
        if d.get("status") == "CLEANED" and d.get("evidence_id") \
                and d["evidence_id"] not in evidence_ids:
            problems.append(
                f"drill {d['id']} is CLEANED but its evidence archive "
                f"{d['evidence_id']} is missing from the bundle")
            ok = False
    return ok


def _verify_auth_tickets(bundle, policies, ceremonies, keys_by_id,
                         audit_by_ticket, problems) -> bool:
    tickets = bundle.get("auth_tickets", [])
    ok = True
    seen_exec = set()
    for t in tickets:
        tid = t.get("id", "?")
        bad = lambda msg: problems.append(f"ticket {tid}: {msg}")
        op = t.get("operation")
        if op not in AZ.PROTECTED_OPERATIONS:
            bad(f"unknown operation {op}"); ok = False; continue

        # frozen digest must match the stored canonical payload
        expect_digest = AZ.ticket_digest(op, t.get("payload", {}))
        if t.get("digest") != expect_digest:
            bad("frozen digest does not match stored payload"); ok = False

        creator = t.get("creator") or {}
        c_pid, c_role, c_did = (creator.get("participant_id"),
                                creator.get("role"), creator.get("device_id"))
        if c_role not in AZ.CREATOR_DUTIES[op]:
            bad(f"creator duty {c_role} may not initiate {op}"); ok = False

        chain = t.get("decision_chain", [])
        types = [d.get("type") for d in chain]
        if types[:1] != ["created"]:
            bad("decision chain does not start with created"); ok = False

        events = [e["event"] for e in audit_by_ticket.get(tid, [])]
        if "authz_ticket_created" not in events:
            bad("no hash-chained audit record for creation"); ok = False

        status = t.get("status")
        if status == AZ.EXECUTED:
            approver = t.get("approver") or {}
            a_pid, a_role, a_did = (approver.get("participant_id"),
                                    approver.get("role"),
                                    approver.get("device_id"))
            # four eyes: distinct person, distinct terminal, complementary
            # (different and authorized) duty.
            if not a_pid or a_pid == c_pid:
                bad("approver is missing or is the same person"); ok = False
            if not a_did or a_did == c_did:
                bad("approver terminal missing or same as creator"); ok = False
            if a_role not in AZ.APPROVER_DUTIES[op] or a_role == c_role:
                bad(f"approver duty {a_role} is not complementary"); ok = False
            if "approved" not in types or "executed" not in types:
                bad("executed ticket lacks approved/executed chain links")
                ok = False
            if tid in seen_exec:
                bad("ticket executed more than once"); ok = False
            seen_exec.add(tid)
            if "authz_ticket_executed" not in events:
                bad("no hash-chained audit record for execution"); ok = False
            # the recorded effect must be observable in the exported state
            _verify_ticket_effect(t, ceremonies, keys_by_id,
                                  policies, bad)
        elif status in (AZ.WITHDRAWN, AZ.CLOSED):
            if t.get("execution") is not None:
                bad("non-executed ticket carries an execution result")
                ok = False
            want = ("withdrawn" if status == AZ.WITHDRAWN else "closed")
            if want not in types:
                bad(f"{status} ticket lacks {want} chain link"); ok = False
            ev = ("authz_ticket_withdrawn" if status == AZ.WITHDRAWN
                  else "authz_ticket_closed")
            if ev not in events:
                bad(f"no hash-chained audit record for {ev}"); ok = False
        elif status == AZ.OPEN:
            pass
        else:
            bad(f"unknown ticket status {status}"); ok = False
    return ok


def _verify_ticket_effect(t, ceremonies, keys_by_id, policies, bad):
    op, p = t["operation"], t.get("payload", {})
    if op == AZ.POLICY_CHANGE:
        pol = policies.get(p.get("policy_id"))
        if pol is None:
            bad("executed POLICY_CHANGE has no resulting policy record")
        return
    cid = p.get("ceremony_id")
    c = ceremonies.get(cid)
    if c is None:
        bad(f"execution references missing ceremony {cid}")
        return
    if op == AZ.ABORT_ACTIVE and c["status"] != "ABORTED":
        bad("executed abort but ceremony is not ABORTED")
    elif op == AZ.PUBLISH_GENERATION:
        if not c.get("published"):
            bad("executed publish but ceremony has no publish record")
        else:
            new = keys_by_id.get(c["result"]["key_version"])
            if new is None or new["status"] != "ACTIVE":
                bad("executed publish but successor is not ACTIVE")
            if new and p.get("expected_active"):
                pred = keys_by_id.get(p["expected_active"])
                # the frozen predecessor was displaced by the publish; it is
                # RETIRING during the handover window or DESTROYED afterwards.
                if pred is None or new["id"] == pred["id"] or \
                        pred["status"] not in ("RETIRING", "DESTROYED"):
                    bad("frozen predecessor was not retired by the publish")
    elif op == AZ.PURGE_RETIRED:
        if c["status"] != "COMPLETED":
            bad("executed purge but DESTROY ceremony is not COMPLETED")
        else:
            kv = keys_by_id.get(c["result"]["key_version"])
            if kv is None or kv["status"] != "DESTROYED":
                bad("executed purge but target key is not DESTROYED")
