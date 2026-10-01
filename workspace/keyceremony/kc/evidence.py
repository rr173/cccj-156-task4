"""Verifiable evidence archives for disaster recovery drills.

An evidence archive is produced when a drill is terminated and cleaned up.
It contains only hashes, summaries and public material - never sealed root
material or credential secrets:

  * recovery point manifest (object list + hashes),
  * blueprint summary (pinned config sequences, categories, RTO/RPO),
  * ordered stage checkpoints with idempotency keys,
  * probe input/output summaries,
  * mirror comparison statistics,
  * lease history,
  * failback and cleanup results.

The whole manifest is signed by the long-lived service identity, and every
constituent section carries a recomputable digest. An independent checker
(`verify_evidence`) recomputes object hashes and the stage order and detects:

  * forged recovery points (manifest hash mismatch),
  * skipped probes / missing stages,
  * duplicate stages or repeated idempotency keys,
  * mirror requests outside an observation window,
  * overlapping or multiply-held leases,
  * evidence gaps (a section the lifecycle required is missing).

Old-format archives ("kc-drill-evidence-v1") remain readable: the verifier
normalizes them before running the checks.
"""

from __future__ import annotations

import copy
import time

from . import crypto, ed25519
from .errors import EvidenceError
from .drills import (
    ENGINE_STAGES, STAGE_PROBES, STAGE_READY, DRILL_CLEANED,
)

CURRENT_FORMAT = "kc-drill-evidence-v2"
READABLE_FORMATS = ("kc-drill-evidence-v1", CURRENT_FORMAT)


def build_evidence(d: dict, service_seed: bytes, clock=time.time) -> dict:
    """Assemble the signed evidence archive from a drill record."""
    bp = d["blueprint"]
    rp_summary = {
        "recovery_point": bp["recovery_point"],
        "source_region": bp["source_region"],
        "source_manifest_hash": bp["source_manifest_hash"],
        "source_config_seq": bp["source_config_seq"],
        "target_config_seq": bp["target_config_seq"],
        "objects": [
            {"key": o["key"], "dest_key": o["dest_key"],
             "body_hash": o["body_hash"], "size": o["size"],
             "category": o["category"], "sealed": o["sealed"],
             "encapsulation_alg": (o["encapsulation"] or {}).get("alg")}
            for o in bp["objects"]
        ],
    }
    rp_summary["objects_list_hash"] = crypto.digest_hex(sorted(
        ({"key": o["key"], "body_hash": o["body_hash"], "size": o["size"],
          "category": o["category"]}
         for o in rp_summary["objects"]), key=lambda o: o["key"]))
    blueprint_summary = {
        "blueprint_hash": d["blueprint_hash"],
        "allowed_categories": bp["allowed_categories"],
        "rto_seconds": bp["rto_seconds"],
        "rpo_seconds": bp["rpo_seconds"],
        "dependency_versions": bp["dependency_versions"],
        "total_size": bp["total_size"],
        "namespace": bp["namespace"],
    }
    checkpoints = [
        {"stage": c["stage"], "checkpoint_id": c["checkpoint_id"],
         "idempotency_key": c["idempotency_key"],
         "confirmed_at": c["confirmed_at"], "detail": c["detail"]}
        for c in d["checkpoints"]
    ]
    probes = [
        {"probe_id": p["probe_id"], "kind": p["kind"],
         "request_hash": p["request_hash"],
         "source_result_hash": p["source_result_hash"],
         "shadow_result_hash": p["shadow_result_hash"],
         "passed": p["passed"], "latency_ms": p.get("latency_ms")}
        for p in d["probes"]
    ]
    stats = dict(d["mirror"]["stats"])
    mirror = {
        "stats": stats,
        "tolerance": {
            "diff_threshold": d["fields"]["diff_threshold"],
            "mismatch_count": d["mirror"].get("mismatch_count",
                                               len(d["mirror"]["differences"])),
            "trigger_request_id": (
                (d["mirror"]["freeze_events"][-1]["request_id"]
                 if d["mirror"].get("freeze_events") else None)),
        },
        "freeze_events": [
            {"request_id": e["request_id"], "reason": e["reason"],
             "at": e["at"], "diff_threshold": e["diff_threshold"],
             "mismatch_count": e["mismatch_count"],
             "resumed_at": e.get("resumed_at"), "resumed_by": e.get("resumed_by")}
            for e in d["mirror"].get("freeze_events", [])
        ],
        "window": d.get("window"),
        "requests": [
            {"request_id": r["request_id"], "operation": r["operation"],
             "at": r["at"], "mirrored": r["mirrored"],
             "in_window": r["in_window"], "routed_to": r["routed_to"],
             "client_forced_mirror": r.get("client_forced_mirror", False),
             "differences": r.get("differences", [])}
            for r in d["mirror"]["requests"]
        ],
        "differences": [
            {"request_id": x["request_id"], "operation": x["operation"],
             "at": x["at"], "differences": x["differences"],
             "mismatch_number": x.get("mismatch_number"),
             "production_result_hash": x["production_result_hash"],
             "shadow_result_hash": x["shadow_result_hash"],
             "archived": x.get("archived", False)}
            for x in d["mirror"]["differences"]
        ],
    }
    lease = d.get("lease")
    lease_section = None
    if lease:
        lease_section = {
            "lease_id": lease["lease_id"],
            "status": lease["status"],
            "holder_instance": lease["holder_instance"],
            "acquired_at": lease["acquired_at"],
            "expires_at": lease["expires_at"],
            "scope": lease["scope"],
            "history": list(lease["history"]),
        }
    cleanup = d.get("cleanup") or {}
    manifest = {
        "format": CURRENT_FORMAT,
        "evidence_id": "ev_" + crypto.digest_hex(
            {"drill": d["id"], "at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime())})[:24],
        "drill_id": d["id"],
        "plan_id": d["plan_id"],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime(clock())),
        "final_status": d["status"],
        "recovery_point": rp_summary,
        "blueprint": blueprint_summary,
        "checkpoints": checkpoints,
        "probes": probes,
        "mirror": mirror,
        "lease": lease_section,
        "failback": d.get("failback"),
        "cleanup": {
            "phase": cleanup.get("phase"),
            "done": list(cleanup.get("done", [])),
            "completed_at": cleanup.get("completed_at"),
        },
    }
    manifest["sections"] = _section_hashes(manifest)
    manifest["manifest_hash"] = crypto.digest_hex(
        {k: v for k, v in manifest.items()
         if k not in ("manifest_hash", "service_sig", "sections")})
    manifest["service_sig"] = crypto.b64e(
        ed25519.sign(service_seed, manifest["manifest_hash"].encode()))
    return manifest


def _section_names() -> tuple:
    return ("recovery_point", "blueprint", "checkpoints", "probes",
            "mirror", "lease", "failback", "cleanup")


def _section_hashes(manifest: dict) -> dict:
    return {name: crypto.digest_hex(manifest.get(name))
            for name in _section_names()}


def normalize(ev: dict) -> dict:
    """Bring an old-format archive up to the current shape for checking."""
    fmt = ev.get("format", "kc-drill-evidence-v1")
    if fmt not in READABLE_FORMATS:
        raise EvidenceError(f"unknown evidence format {fmt}")
    if fmt == CURRENT_FORMAT:
        return ev
    # v1 -> v2: older archives lacked per-section hashes and the namespace in
    # the blueprint summary; fill what can be derived and mark the upgrade.
    out = dict(ev)
    out["format"] = CURRENT_FORMAT
    out["upgraded_from"] = fmt
    bp = out.get("blueprint")
    if isinstance(bp, dict) and "namespace" not in bp:
        bp["namespace"] = None
    if "sections" not in out:
        out["sections"] = _section_hashes(out)
    # v1 archives did not record the independent object-list digest; derive it
    # from the carried object list so the remaining checks still apply.
    rp = out.get("recovery_point")
    if isinstance(rp, dict) and "objects_list_hash" not in rp and \
            rp.get("objects") is not None:
        rp["objects_list_hash"] = crypto.digest_hex(sorted(
            ({"key": o["key"], "body_hash": o["body_hash"], "size": o["size"],
              "category": o["category"]}
             for o in rp.get("objects", [])), key=lambda o: o["key"]))
    # older lease records may lack the scope/history fields
    lease = out.get("lease")
    if lease and "history" not in lease:
        lease["history"] = [
            {"at": lease.get("acquired_at"), "event": "acquired",
             "instance": lease.get("holder_instance")}]
    return out


def verify_evidence(ev: dict, *, expect_final_status: str | None = None,
                    require_cleaned: bool = True) -> dict:
    """Recompute every hash and validate the lifecycle structure.

    Returns {"ok", "problems", "checks"}. `problems` contains explicit,
    human-readable failure reasons for each detected forgery/gap.
    """
    problems: list[str] = []
    original_format = ev.get("format", "kc-drill-evidence-v1")
    # The manifest hash is computed over the *as-presented* content; the
    # normalizer below only fills structural gaps for the lifecycle checks and
    # must not change what the signature/hashes are validated against.
    hash_ev = copy.deepcopy(ev)
    try:
        ev = normalize(ev)
    except EvidenceError as e:
        return {"ok": False, "problems": [str(e)], "checks": {}}

    # 1. manifest integrity: rehash every section and the whole manifest.
    # Old (v1) archives predate per-section hashes; the manifest hash and the
    # service signature (checked by the bundle verifier) cover them instead.
    is_legacy = original_format != CURRENT_FORMAT
    if not is_legacy and hash_ev.get("sections"):
        for name, h in _section_hashes(hash_ev).items():
            if hash_ev["sections"].get(name) != h:
                problems.append(
                    f"evidence section '{name}' was modified after sealing")
    # The manifest hash signs all content fields, excluding the derived
    # section hashes and the signature fields themselves. Legacy archives
    # carry no sections map at all.
    excluded = {"manifest_hash", "service_sig"}
    if not is_legacy:
        excluded.add("sections")
    body_hash = crypto.digest_hex(
        {k: v for k, v in hash_ev.items() if k not in excluded})
    manifest_ok = body_hash == hash_ev.get("manifest_hash")
    if not manifest_ok:
        problems.append("evidence manifest hash mismatch (archive edited)")

    # 2. recovery point: the archive binds the snapshot manifest hash pinned
    # by the blueprint; the object list itself is section-signed (step 1) so
    # a forged recovery point editing any object hash breaks section
    # integrity. Independently recompute the object-list digest so a forger
    # cannot just re-seal sections without a service key.
    rp = ev.get("recovery_point", {})
    bp = ev.get("blueprint", {})
    if not rp.get("source_manifest_hash"):
        problems.append(
            "evidence gap: recovery point manifest hash not recorded")
    if rp.get("source_region") != bp.get("source_region") and \
            bp.get("source_region") is not None:
        problems.append("recovery point region does not match blueprint")
    recomputed_objs = crypto.digest_hex(sorted(
        ({"key": o["key"], "body_hash": o["body_hash"],
          "size": o["size"], "category": o["category"]}
         for o in rp.get("objects", [])), key=lambda o: o["key"]))
    if rp.get("objects_list_hash") and \
            rp["objects_list_hash"] != recomputed_objs:
        problems.append(
            "recovery point object list digest mismatch (forged objects)")
    if not rp.get("objects"):
        problems.append("evidence gap: recovery point object list is empty")
    # every key-material object recorded must be sealed
    for o in rp.get("objects", []):
        if o.get("category") == "key_material" and not o.get("sealed"):
            problems.append(
                f"recovery object {o.get('key')} records unsealed root "
                "material")

    # 3. stage order: strict engine order, no skips, no duplicates
    cps = ev.get("checkpoints", [])
    stages = [c["stage"] for c in cps]
    want_order = list(ENGINE_STAGES) + [STAGE_READY]
    seen = set()
    for s in stages:
        if s in seen:
            problems.append(f"duplicate stage checkpoint: {s}")
        seen.add(s)
    idem = [c.get("idempotency_key") for c in cps]
    if len([k for k in idem if k]) != len(set(k for k in idem if k)):
        problems.append("duplicate stage idempotency keys")
    if require_cleaned:
        prefix = [s for s in stages if s != STAGE_READY]
        expected_prefix = want_order[:len(prefix)]
        if prefix != expected_prefix:
            problems.append(
                f"stages skipped or out of order: {prefix} "
                f"(expected prefix of {want_order})")
        if STAGE_PROBES not in stages:
            problems.append("evidence gap: PROBES stage missing")
        if STAGE_READY not in stages:
            problems.append("evidence gap: READY checkpoint missing")

    # 4. probes: none skipped, hashes consistent, every probe passed
    probes = ev.get("probes", [])
    kinds = [p["kind"] for p in probes]
    if not any(k == "OBJECT_HASH" for k in kinds):
        problems.append("evidence gap: no OBJECT_HASH probes recorded")
    if not any(k == "INDEX_LOOKUP" for k in kinds):
        problems.append("evidence gap: no INDEX_LOOKUP probes recorded")
    seen_probes = set()
    for p in probes:
        if p["probe_id"] in seen_probes:
            problems.append(f"duplicate probe recorded: {p['probe_id']}")
        seen_probes.add(p["probe_id"])
        if not p.get("passed"):
            problems.append(f"probe {p['probe_id']} did not pass")
        if p.get("source_result_hash") == p.get("shadow_result_hash"):
            pass
        else:
            problems.append(
                f"probe {p['probe_id']} source/shadow result hashes differ")

    # 5. mirror traffic: every mirrored request must be inside a window
    mirror = ev.get("mirror", {})
    w = mirror.get("window")
    window_bounds = None
    if w and w.get("opened_at") is not None:
        window_bounds = (w["opened_at"],
                         w.get("closes_at", w.get("closed_at")))
    forced_outside = 0
    for r in mirror.get("requests", []):
        if r.get("mirrored") and not r.get("in_window"):
            problems.append(
                f"request {r['request_id']} was mirrored outside an "
                "observation window")
        if r.get("client_forced_mirror") and not r.get("mirrored") \
                and r.get("operation") == "SIGN":
            forced_outside += 1
    # writes must never be mirrored
    for r in mirror.get("requests", []):
        if r.get("operation") in ("SIGN", "ROTATE", "GENERATE", "DESTROY",
                                  "POLICY_CHANGE") and r.get("mirrored"):
            problems.append(
                f"write operation {r['operation']} ({r['request_id']}) was "
                "mirrored into the isolated region")
    stats = mirror.get("stats", {})
    if stats:
        accounted = (stats.get("matched", 0) + stats.get("differences", 0))
        if accounted > stats.get("mirrored", 0):
            problems.append(
                "mirror stats inconsistent: matched+differences exceed "
                "mirrored total")

    # 5b. mismatch tolerance accounting: the accumulated count must equal the
    # distinct difference records (no double counting, no gaps), the quota is
    # a non-negative integer, and every freeze event's quota/count/trigger
    # correlation id must agree with the difference record at that tally.
    tol = mirror.get("tolerance")
    if tol is not None:
        diffs = mirror.get("differences", [])
        quota = tol.get("diff_threshold", 0)
        if not isinstance(quota, int) or isinstance(quota, bool) or quota < 0:
            problems.append(
                "mirror tolerance quota must be a non-negative integer")
        rids = [x.get("request_id") for x in diffs]
        if len(rids) != len(set(rids)):
            problems.append(
                "mirror differences contain a repeated request correlation "
                "id (the same mismatch was counted twice)")
        if tol.get("mismatch_count") != len(diffs):
            problems.append(
                "mirror tolerance mismatch_count disagrees with the number "
                "of difference records (count not continuous or double "
                "counted)")
        # difference records carry the continuous 1-based tally at which each
        # mismatch was first seen: the numbers form a gap-free sequence.
        numbers = [x.get("mismatch_number") for x in diffs]
        present = sorted(n for n in numbers if n is not None)
        if present and present != list(range(1, len(present) + 1)):
            problems.append(
                "mirror mismatch numbers are not a continuous 1-based "
                "sequence")
        events = mirror.get("freeze_events", [])
        by_rid = {x.get("request_id"): x for x in diffs}
        for e in events:
            n = e.get("mismatch_count")
            eq = e.get("diff_threshold", quota)
            if not isinstance(n, int) or not isinstance(eq, int) or n <= eq:
                problems.append(
                    f"freeze event {e.get('request_id')} was recorded before "
                    "the mismatch count exceeded the tolerance quota")
                continue
            rid = e.get("request_id")
            rec = by_rid.get(rid)
            if rec is None:
                problems.append(
                    f"freeze trigger correlation id {rid} is not among the "
                    "recorded differences")
            elif rec.get("mismatch_number") != n:
                problems.append(
                    f"freeze trigger {rid} tally {n} disagrees with the "
                    "difference record's mismatch number")
            if eq != quota:
                problems.append(
                    f"freeze event {rid} quota disagrees with the tolerance "
                    "configuration")
        if tol.get("trigger_request_id") != (
                events[-1].get("request_id") if events else None):
            problems.append(
                "tolerance trigger correlation id does not match the latest "
                "freeze event")
        # if the total never exceeded the quota, mirroring must never have
        # frozen (converse is already covered per event above)
        if not events and len(diffs) > quota:
            problems.append(
                "mismatch count exceeded the tolerance quota but no freeze "
                "event was recorded")

    # 6. lease history: at most one held interval, no overlap
    lease = ev.get("lease")
    if lease:
        hist = lease.get("history", [])
        acquisitions = [h for h in hist if h.get("event") == "acquired"]
        if len(acquisitions) > 1:
            problems.append(
                f"lease acquired {len(acquisitions)} times: overlapping "
                "failover holders")
        held_events = [h for h in hist if h.get("event") == "acquired"]
        if held_events and lease.get("scope") != \
                "read_only_verification_ingress":
            problems.append("lease scope is not read-only verification ingress")
        if lease.get("status") == "HELD" and require_cleaned:
            problems.append("archive finalized while a lease was still HELD")
        if not hist:
            problems.append("evidence gap: lease record has no history")

    # 7. failback + cleanup evidence. Evidence is archived at the end of
    # cleanup (so the archive records CLEANED + the complete phase list);
    # REVOKE_CREDENTIALS and DELETE_RESOURCES precede it in the live run.
    fb = ev.get("failback")
    if lease and fb is None and require_cleaned:
        problems.append("evidence gap: lease exists but failback result missing")
    if fb and fb.get("read_ingress") != "production":
        problems.append("failback did not return read ingress to production")
    cleanup = ev.get("cleanup", {})
    if require_cleaned:
        done = cleanup.get("done", [])
        for phase in ("REVOKE_CREDENTIALS", "DELETE_RESOURCES"):
            if phase not in done:
                problems.append(f"evidence gap: cleanup phase {phase} missing")
        if ev.get("final_status") == DRILL_CLEANED and \
                "ARCHIVE_EVIDENCE" not in done:
            # the archive's own existence is the evidence; only flag when it
            # does not even carry the sealing marker
            if not ev.get("manifest_hash"):
                problems.append("evidence gap: cleanup phase "
                                "ARCHIVE_EVIDENCE missing")
        if ev.get("final_status") != DRILL_CLEANED:
            problems.append(
                f"evidence final_status is {ev.get('final_status')}, "
                f"expected {DRILL_CLEANED}")

    checks = {
        "manifest_hash_ok": manifest_ok,
        "sections_intact": not any("section" in p for p in problems),
        "recovery_point_ok": not any(
            "recovery" in p or "recovery object" in p for p in problems),
        "stage_order_ok": not any(
            "stage" in p or "stages" in p for p in problems),
        "probes_ok": not any("probe" in p for p in problems),
        "mirror_isolation_ok": not any(
            "mirror" in p or "write operation" in p for p in problems),
        "lease_ok": not any("lease" in p for p in problems),
        "failback_cleanup_ok": not any(
            "failback" in p or "cleanup" in p for p in problems),
    }
    return {"ok": not problems, "problems": problems, "checks": checks,
            "format": ev.get("format"),
            "upgraded_from": ev.get("upgraded_from")}


def verify_evidence_signature(ev: dict, service_pub: bytes) -> bool:
    """Check the service identity signature over the manifest hash."""
    sig = ev.get("service_sig")
    if not sig:
        return False
    try:
        return ed25519.verify(service_pub,
                             ev["manifest_hash"].encode(),
                             crypto.b64d(sig))
    except Exception:
        return False
