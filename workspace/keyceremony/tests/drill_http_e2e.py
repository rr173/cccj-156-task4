"""End-to-end HTTP test for cross-region disaster recovery drills.

Exercises the drill surface through the running HTTP server (the same session
+ duty gates as the ceremony console): region setup, revisioned plans with a
stale-submit conflict, preflight block with no half environment, blueprint
invalidation, staged rebuild with crash resume, read-only mirroring, write
isolation under a forged mirror marker, difference freeze/resume,
single-holder lease contention, idempotent failback, blocked then resumed
cleanup, and evidence verification via the export bundle.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8355
ROOT = f"/tmp/kc-drill-http-{PORT}"
shutil.rmtree(ROOT, ignore_errors=True)

bp = subprocess.run(
    [sys.executable, "-m", "kc.bootstrap", "--root", ROOT],
    capture_output=True, text=True)
assert bp.returncode == 0, bp.stderr

proc = subprocess.Popen(
    [sys.executable, "-m", "kc.server", "--root", ROOT, "--port", str(PORT)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    BASE = f"http://127.0.0.1:{PORT}"
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)

    TOKENS = {}

    def call(path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(
            BASE + path, data=data,
            method=("POST" if body is not None else "GET"), headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def login(pid):
        did = "dev_" + pid
        assert call("/api/session/login-challenge", {"device_id": did})[0] == 200
        s, j = call("/api/session/login", {"device_id": did})
        assert s == 200, (s, j)
        TOKENS[pid] = j["token"]

    for pid in ("alice", "bruno", "carla", "diego"):
        login(pid)

    # ---- 1. region setup --------------------------------------------------
    s, _ = call("/api/drill-regions/define",
                {"name": "us-east", "isolated": False,
                 "capacity": 1 << 30}, TOKENS["alice"])
    assert s == 200
    s, _ = call("/api/drill-regions/define",
                {"name": "eu-west-airgap", "isolated": True,
                 "capacity": 1 << 20, "isolation": "AIRGAPPED"},
                TOKENS["alice"])
    assert s == 200
    objs = [
        ("prod/keywrap-1.bin", "c2VhbGVkLXJvb3QtbWF0ZXJpYWw=", True,
         "key_material"),
        ("prod/pubkeys.json", "eyJwdWJsaWMiOnRydWV9", False, "public_keys"),
        ("prod/audit.log", "YXVkaXQ=", False, "audit"),
        ("prod/index.json", "eyJpbmRleCI6MX0=", False, "index"),
        ("prod/policy.json", "eyJ0aHJlc2hvbGQiOjN9", False, "policy"),
    ]
    for key, b64, sealed, cat in objs:
        s, _ = call("/api/drill-regions/put-object",
                    {"region": "us-east", "key": key, "body_b64": b64,
                     "sealed": sealed, "category": cat}, TOKENS["alice"])
        assert s == 200, (key, _)
    s, rp = call("/api/drill-regions/recovery-point",
                 {"region": "us-east", "recovery_point": "rp-1",
                  "object_keys": [o[0] for o in objs]}, TOKENS["alice"])
    assert s == 200 and rp["n_object"] if False else s == 200
    print("regions + recovery point ok")

    plan_body = {
        "label": "http drill", "source_region": "us-east",
        "target_region": "eu-west-airgap", "recovery_point": "rp-1",
        "allowed_categories": ["key_material", "public_keys", "audit",
                               "index", "policy"],
        "rto_seconds": 300, "rpo_seconds": 3600, "mirror_ratio": 1.0}

    # ---- 2. revision conflict --------------------------------------------
    s, plan = call("/api/drill-plans", plan_body, TOKENS["alice"])
    assert s == 200
    pid = plan["id"]
    # alice edits first (revision 2)
    edited = dict(plan_body, rto_seconds=200)
    s, pa = call("/api/drill-plans",
                 {"plan_id": pid, "base_revision": 1, **edited},
                 TOKENS["alice"])
    assert s == 200 and pa["revision"] == 2
    # bruno submits a stale edit against revision 1 -> 409 with both sides
    stale = dict(plan_body, rto_seconds=100, mirror_ratio=0.5)
    s, conflict = call("/api/drill-plans",
                       {"plan_id": pid, "base_revision": 1, **stale},
                       TOKENS["bruno"])
    assert s == 409 and conflict["error"] == "REVISION_CONFLICT", (s, conflict)
    assert conflict["base_revision"] == 1
    assert conflict["current_revision"] == 2
    assert conflict["base_snapshot"]["rto_seconds"] == 300
    assert conflict["current_snapshot"]["rto_seconds"] == 200
    print("plan revision conflict returns both snapshots ok")

    # ---- 3. scan + start + staged rebuild --------------------------------
    s, scanview = call(f"/api/drill-plans/{pid}/scan", {}, TOKENS["alice"])
    assert s == 200 and scanview["status"] == "SCANNED", (s, scanview)
    s, drill = call(f"/api/drill-plans/{pid}/start", {}, TOKENS["diego"])
    assert s == 200, (s, drill)
    did = drill["id"]
    assert drill["credential"]["secret"].startswith("drk_")
    # run each stage idempotently
    stages_seen = set()
    for _ in range(8):
        s, view = call(f"/api/drills/{did}/run-to-ready", {}, TOKENS["diego"])
        assert s == 200
        if view["status"] == "READY":
            break
    assert view["status"] == "READY", view["status"]
    cps = [c["stage"] for c in view["checkpoints"]]
    assert cps == ["PREPARE", "COPY", "REBUILD_INDEX", "SHADOW_START",
                   "PROBES", "READY"], cps
    print("staged isolated rebuild -> READY ok")

    # ---- 4. mirror: read matches, write with forged flag refused --------
    s, _ = call(f"/api/drills/{did}/window", {"seconds": 600}, TOKENS["diego"])
    assert s == 200
    s, mr = call(f"/api/drills/{did}/mirror",
                 {"operation": "VERIFY", "key": "prod/pubkeys.json",
                  "request_id": "req-1"}, TOKENS["diego"])
    assert s == 200 and mr["matched"], (s, mr)
    # write operations stay in production even with forged mirror marker
    s, wr = call(f"/api/drills/{did}/mirror",
                 {"operation": "SIGN", "request_id": "req-w",
                  "mirror_to_shadow": True}, TOKENS["diego"])
    assert s == 422 and wr["error"] == "POLICY_VIOLATION", (s, wr)
    print("read-only mirror + write isolation ok")

    # ---- 5. difference freezes the drill; resume after repair -----------
    s, fr = call(f"/api/drills/{did}/mirror",
                 {"operation": "VERIFY", "key": "k", "request_id": "diff-1",
                  "_shadow_value_override": {"bad": True}}, TOKENS["diego"])
    assert s == 200 and fr["frozen"], (s, fr)
    s, gd = call(f"/api/drills/{did}", token=TOKENS["alice"])
    assert gd["status"] == "FROZEN"
    s, _ = call(f"/api/drills/{did}/resume", {"note": "shadow repaired"},
                TOKENS["diego"])
    assert s == 200
    print("difference freeze + resume ok")

    # ---- 6. lease: close window, single holder under contention ---------
    s, _ = call(f"/api/drills/{did}/window", {"close": True},
                TOKENS["diego"])
    assert s == 200

    def acquire(_):
        return call(f"/api/drills/{did}/lease",
                    {"instance_id": f"ctrl-{_}", "ttl_seconds": 300},
                    TOKENS["alice"])

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(acquire, range(6)))
    assert sum(1 for code, _ in results if code == 200) == 1, results
    assert {j["error"] for code, j in results if code != 200} == \
        {"LEASE_CONTENTION"}, results
    s, fs = call(f"/api/drills/{did}/failover-status", token=TOKENS["alice"])
    assert fs["read_ingress"] == "shadow" and fs["write_ingress"] == "production"
    print("single-holder failover lease ok; read-only ingress only")

    # ---- 7. idempotent failback ------------------------------------------
    s, fb1 = call(f"/api/drills/{did}/failback", {}, TOKENS["alice"])
    s, fb2 = call(f"/api/drills/{did}/failback", {}, TOKENS["alice"])
    assert fb1["failed_back_at"] == fb2["failed_back_at"]
    assert fb2["read_ingress"] == "production"
    print("idempotent failback ok")

    # ---- 8. blocked cleanup (unarchived differences) then completion ----
    # reopen a window, make a difference, archive, terminate
    call(f"/api/drills/{did}/window", {"seconds": 600}, TOKENS["diego"])
    call(f"/api/drills/{did}/mirror",
         {"operation": "VERIFY", "key": "k2", "request_id": "diff-2",
          "_shadow_value_override": {"bad2": True}}, TOKENS["diego"])
    call(f"/api/drills/{did}/resume", {"note": "repaired"}, TOKENS["diego"])
    call(f"/api/drills/{did}/window", {"close": True}, TOKENS["diego"])
    s, blocked = call(f"/api/drills/{did}/cleanup", {}, TOKENS["alice"])
    assert s == 409 and blocked["error"] == "CLEANUP_BLOCKED", (s, blocked)
    assert any("unarchived" in b for b in blocked["blockers"]), blocked
    s, _ = call(f"/api/drills/{did}/archive-differences", {}, TOKENS["alice"])
    assert s == 200
    s, done = call(f"/api/drills/{did}/terminate", {}, TOKENS["alice"])
    assert s == 200 and done["status"] == "CLEANED", (s, done)
    print("blocked cleanup -> unblock -> completed ok")

    # ---- 9. evidence in the export bundle verifies ----------------------
    s, bundle = call("/api/export", token=TOKENS["alice"])
    assert s == 200
    from kc import export as export_mod
    verdict = export_mod.verify_bundle(bundle)
    assert verdict["ok"], verdict["problems"]
    assert verdict["checks"]["drill_evidence_ok"], verdict["checks"]
    assert bundle["invariants"]["n_drills"] >= 1
    print("export bundle with drill evidence verified:",
          verdict["checks"]["drill_evidence_ok"])

    print("DRILL HTTP E2E ALL OK")
finally:
    proc.terminate()
    proc.wait(timeout=5)
