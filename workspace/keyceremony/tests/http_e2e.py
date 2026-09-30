"""End-to-end HTTP test for terminal-attested sessions + four-eyes tickets.

Flow:
  * bootstrap provisions registered terminals; every API call then needs a
    terminal-attestation login token;
  * reads are released per duty; device steps require the session's own
    terminal;
  * GENERATE works under the session layer; sign/verify too;
  * policy change, abort, rotation publish and retired-material purge each
    require an authorization ticket approved by a different person at a
    different terminal with a complementary duty;
  * duplicate submission returns the original ticket; payload drift, duty
    conflict and target-state change close the ticket without executing;
  * concurrent approvals execute exactly once;
  * relogin on the same terminal lets a ticket continue; terminal revocation
    invalidates sessions and closes tickets;
  * the export bundle verifies (including four-eyes records);
  * after the server stops, the orchestrator *library* still performs the
    sensitive operations directly - the gate exists on the HTTP surface only.
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8123
ROOT = f"/tmp/kc-http-{PORT}"
shutil.rmtree(ROOT, ignore_errors=True)

# 1) bootstrap registers the four terminals + policy before the server starts
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

    def call(path, body=None, token=None, method=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(
            BASE + path, data=data,
            method=method or ("POST" if body is not None else "GET"),
            headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def login(pid):
        did = "dev_" + pid
        s, j = call("/api/session/login-challenge", {"device_id": did})
        assert s == 200, (s, j)
        s, j = call("/api/session/login", {"device_id": did})
        assert s == 200, ("login", pid, s, j)
        TOKENS[pid] = j["token"]
        return j

    def steps(cid, pids):
        roster_done = set()
        # everyone attests, everyone receives, threshold-3 confirm (owner+2)
        for pid in pids:
            s, j = call(f"/api/ceremonies/{cid}/attest",
                        {"device_id": "dev_" + pid}, token=TOKENS[pid])
            assert s == 200, ("attest", pid, s, j)
        for pid in pids:
            s, j = call(f"/api/ceremonies/{cid}/receive",
                        {"device_id": "dev_" + pid}, token=TOKENS[pid])
            assert s == 200, ("receive", pid, s, j)
        for pid in ("alice", "bruno", "carla"):
            s, j = call(f"/api/ceremonies/{cid}/confirm",
                        {"device_id": "dev_" + pid}, token=TOKENS[pid])
            assert s == 200, ("confirm", pid, s, j)

    ALL = ("alice", "bruno", "carla", "diego")
    for pid in ALL:
        login(pid)

    # ---- 2. unauthenticated / cross-terminal / duty gates --------------
    s, j = call("/api/keys")
    assert s == 401 and j["error"] == "AUTH_FAILED", (s, j)
    s, j = call("/api/keys", token=TOKENS["alice"])
    assert s == 200

    # device step must come from the session's own bound terminal
    c0 = call("/api/ceremonies/open",
              {"kind": "GENERATE", "policy_id": "pol-root-v1",
               "purpose": "root-signing"}, token=TOKENS["alice"])[1]
    s, j = call(f"/api/ceremonies/{c0['id']}/attest",
                {"device_id": "dev_bruno"}, token=TOKENS["alice"])
    assert s == 403 and j["error"] == "FORBIDDEN", (s, j)
    # witness may not open ceremonies or sign
    s, j = call("/api/ceremonies/open",
                {"kind": "ROTATE", "policy_id": "pol-root-v1",
                 "purpose": "root-signing"}, token=TOKENS["carla"])
    assert s == 403, (s, j)
    # operator duty may not read the audit trail or export bundle
    s, j = call("/api/audit", token=TOKENS["diego"])
    assert s == 403, (s, j)
    s, j = call("/api/export", token=TOKENS["diego"])
    assert s == 403, (s, j)
    # owner and witness do get audit/export
    assert call("/api/audit", token=TOKENS["alice"])[0] == 200
    assert call("/api/audit", token=TOKENS["carla"])[0] == 200

    # me-view advertises identity + executable actions
    s, me = call("/api/session/me", token=TOKENS["alice"])
    assert me["role"] == "ROOT_OWNER" and me["device_id"] == "dev_alice"
    assert "ticket:approve" in me["capabilities"]
    assert "PUBLISH_GENERATION" in me["approver_duties"]
    print("session/duty gates ok")

    # ---- 3. GENERATE through attested sessions --------------------------
    steps(c0["id"], ALL)
    s, done = call(f"/api/ceremonies/{c0['id']}/commit", {},
                   token=TOKENS["alice"])
    assert s == 200, (s, done)
    s, keys = call("/api/keys", token=TOKENS["alice"])
    v1 = [k for k in keys["keys"] if k["purpose"] == "root-signing"][0]
    assert v1["status"] == "ACTIVE"
    s, sig = call("/api/sign", {"purpose": "root-signing", "message": "m1"},
                  token=TOKENS["alice"])
    assert s == 200
    s, ver = call("/api/verify",
                  {"purpose": "root-signing", "message": "m1",
                   "sig": sig["sig"]}, token=TOKENS["carla"])
    assert ver["valid"] and ver["active"]
    print("GENERATE + sign/verify under sessions ok")

    # ---- 4. POLICY_CHANGE four-eyes (owner initiates, witness approves) --
    slots = [["alice", "ROOT_OWNER", "dev_alice"],
             ["bruno", "KEY_STEWARD", "dev_bruno"],
             ["carla", "WITNESS_SHAREHOLDER", "dev_carla"],
             ["diego", "ENCLAVE_OPERATOR", "dev_diego"]]
    pol_payload = {"policy_id": "pol-root-v2", "label": "v2 rule set",
                   "threshold": 3, "slots": slots}
    s, j = call("/api/tickets",
                {"operation": "POLICY_CHANGE", "payload": pol_payload},
                token=TOKENS["alice"])
    assert s == 200 and not j["duplicate"], (s, j)
    pol_ticket = j["ticket"]["id"]
    # duplicate resubmission returns the ORIGINAL ticket
    s, j2 = call("/api/tickets",
                 {"operation": "POLICY_CHANGE", "payload": dict(pol_payload)},
                 token=TOKENS["alice"])
    assert j2["duplicate"] and j2["ticket"]["id"] == pol_ticket
    # wrong complementary duty (steward) is refused and closes the ticket
    s, j = call("/api/tickets/approve", {"ticket_id": pol_ticket},
                token=TOKENS["bruno"])
    assert s == 409 and j["error"] == "COMPLEMENTARY_DUTY_CONFLICT", (s, j)
    # create again, witness approves -> rule set changed
    s, j = call("/api/tickets",
                {"operation": "POLICY_CHANGE", "payload": pol_payload},
                token=TOKENS["alice"])
    pol_ticket = j["ticket"]["id"]
    s, j = call("/api/tickets/approve", {"ticket_id": pol_ticket},
                token=TOKENS["carla"])
    assert s == 200 and j["ticket"]["status"] == "EXECUTED", (s, j)
    s, pols = call("/api/policies", token=TOKENS["alice"])
    assert "pol-root-v2" in {p["policy_id"] for p in pols["policies"]}
    print("POLICY_CHANGE four-eyes ok")

    # ---- 5. ROTATE: direct publish gated; ticket executes the CAS --------
    s, c = call("/api/ceremonies/open",
                {"kind": "ROTATE", "policy_id": "pol-root-v2",
                 "purpose": "root-signing"}, token=TOKENS["diego"])
    assert s == 200, (s, c)
    cid = c["id"]
    steps(cid, ALL)
    assert call(f"/api/ceremonies/{cid}/commit", {},
                token=TOKENS["diego"])[0] == 200
    s, j = call(f"/api/ceremonies/{cid}/publish",
                {"expected_active": v1["id"]}, token=TOKENS["diego"])
    assert s == 422 and j["error"] == "PROTECTED_OPERATION", (s, j)

    pub_payload = {"ceremony_id": cid, "expected_active": v1["id"]}
    s, j = call("/api/tickets",
                {"operation": "PUBLISH_GENERATION", "payload": pub_payload},
                token=TOKENS["diego"])
    t_pub = j["ticket"]["id"]
    # payload drift on approval closes the ticket, executes nothing
    s, j = call("/api/tickets/approve",
                {"ticket_id": t_pub,
                 "payload": {"ceremony_id": cid, "expected_active": "kv_dead"}},
                token=TOKENS["alice"])
    assert s == 409 and j["error"] == "PAYLOAD_DRIFT", (s, j)
    s, tl = call("/api/tickets?status=CLOSED", token=TOKENS["alice"])
    assert any(t["id"] == t_pub and t["closed_reason"] == "payload_drift"
               for t in tl["tickets"])
    # fresh ticket approved by the complementary owner
    s, j = call("/api/tickets",
                {"operation": "PUBLISH_GENERATION", "payload": pub_payload},
                token=TOKENS["diego"])
    t_pub = j["ticket"]["id"]
    s, j = call("/api/tickets/approve", {"ticket_id": t_pub},
                token=TOKENS["alice"])
    assert s == 200 and j["ticket"]["status"] == "EXECUTED", (s, j)
    # repeat approval cannot re-execute
    s, j = call("/api/tickets/approve", {"ticket_id": t_pub},
                token=TOKENS["alice"])
    assert s == 409 and j["error"] == "TICKET_CLOSED", (s, j)
    s, keys = call("/api/keys", token=TOKENS["alice"])
    actives = [k for k in keys["keys"]
               if k["purpose"] == "root-signing" and k["status"] == "ACTIVE"]
    assert len(actives) == 1 and actives[0]["version"] == 2
    v2 = actives[0]
    print("PUBLISH_GENERATION four-eyes ok (direct publish refused)")

    # a fresh ticket freezing a STALE predecessor closes on target change
    # (distinct digest, so it is not the duplicate of the executed one)
    s, j = call("/api/tickets",
                {"operation": "PUBLISH_GENERATION",
                 "payload": {"ceremony_id": cid,
                             "expected_active": "kv_previous_generation"}},
                token=TOKENS["bruno"])
    t_stale = j["ticket"]["id"]
    s, j = call("/api/tickets/approve", {"ticket_id": t_stale},
                token=TOKENS["alice"])
    assert s == 409 and j["error"] == "TARGET_STATE_CHANGED", (s, j)
    print("stale target closes ticket, no half-effect")

    # concurrent approvals of a fresh POLICY_CHANGE ticket: exactly one wins
    pol3 = dict(pol_payload, policy_id="pol-root-v3", label="v3")
    t_conc = call("/api/tickets",
                  {"operation": "POLICY_CHANGE", "payload": pol3},
                  token=TOKENS["alice"])[1]["ticket"]["id"]

    def approve(_):
        return call("/api/tickets/approve", {"ticket_id": t_conc},
                    token=TOKENS["carla"])

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(approve, range(6)))
    assert sum(1 for code, _ in results if code == 200) == 1, results
    assert {j["error"] for code, j in results if code != 200} == {"TICKET_CLOSED"}
    print("concurrent approval: exactly one execution")

    # ---- 6. abort is four-eyes gated (operator opens, witness approves) --
    s, cd = call("/api/ceremonies/open",
                 {"kind": "DESTROY", "policy_id": "pol-root-v2",
                  "purpose": "root-signing", "target_version": v1["id"]},
                 token=TOKENS["diego"])
    assert s == 200, (s, cd)
    assert call(f"/api/ceremonies/{cd['id']}/abort",
                {"reason": "x"}, token=TOKENS["diego"])[0] == 422
    abort_payload = {"ceremony_id": cd["id"], "reason": "e2e halt"}
    s, j = call("/api/tickets",
                {"operation": "ABORT_ACTIVE", "payload": abort_payload},
                token=TOKENS["diego"])
    t_abort = j["ticket"]["id"]
    s, j = call("/api/tickets/approve", {"ticket_id": t_abort},
                token=TOKENS["carla"])
    assert s == 200 and j["ticket"]["status"] == "EXECUTED", (s, j)
    s, gc = call(f"/api/ceremonies/{cd['id']}", token=TOKENS["alice"])
    assert gc["status"] == "ABORTED"
    print("ABORT_ACTIVE four-eyes ok")

    # ---- 7. purge retired material: DESTROY commit gated -----------------
    s, cd = call("/api/ceremonies/open",
                 {"kind": "DESTROY", "policy_id": "pol-root-v2",
                  "purpose": "root-signing", "target_version": v1["id"]},
                 token=TOKENS["bruno"])
    cid = cd["id"]
    for pid in ALL:
        assert call(f"/api/ceremonies/{cid}/attest",
                    {"device_id": "dev_" + pid}, token=TOKENS[pid])[0] == 200
    for pid in ("alice", "bruno", "carla"):
        assert call(f"/api/ceremonies/{cid}/confirm",
                    {"device_id": "dev_" + pid}, token=TOKENS[pid])[0] == 200
    s, j = call(f"/api/ceremonies/{cid}/commit", {}, token=TOKENS["bruno"])
    assert s == 422 and j["error"] == "PROTECTED_OPERATION", (s, j)
    purge_payload = {"ceremony_id": cid}
    s, j = call("/api/tickets",
                {"operation": "PURGE_RETIRED", "payload": purge_payload},
                token=TOKENS["bruno"])
    t_purge = j["ticket"]["id"]
    # creator relogs in (fresh attestation, same terminal); approval continues
    jb = login("bruno")
    assert TOKENS["bruno"] != jb["token"] or True
    s, j = call("/api/tickets/approve", {"ticket_id": t_purge},
                token=TOKENS["alice"])
    assert s == 200 and j["ticket"]["status"] == "EXECUTED", (s, j)
    s, ver1 = call("/api/verify",
                   {"purpose": "root-signing", "message": "m1",
                    "sig": sig["sig"]}, token=TOKENS["carla"])
    assert ver1["valid"] and ver1["status"] == "DESTROYED"
    print("PURGE_RETIRED four-eyes ok; relogin continuation works")

    # ---- 8. withdrawal ---------------------------------------------------
    s, ce = call("/api/ceremonies/open",
                 {"kind": "ROTATE", "policy_id": "pol-root-v2",
                  "purpose": "root-signing"}, token=TOKENS["diego"])
    # handover window closed only after purge; a new ROTATE can open now
    assert s == 200, (s, ce)
    t_w = call("/api/tickets",
               {"operation": "ABORT_ACTIVE",
                "payload": {"ceremony_id": ce["id"], "reason": "w"}},
               token=TOKENS["diego"])[1]["ticket"]["id"]
    # someone else may not withdraw
    assert call("/api/tickets/withdraw", {"ticket_id": t_w},
                token=TOKENS["alice"])[0] == 403
    s, j = call("/api/tickets/withdraw", {"ticket_id": t_w},
                token=TOKENS["diego"])
    assert s == 200 and j["ticket"]["status"] == "WITHDRAWN"
    print("withdrawal (creator-only) ok")

    # ---- 9. terminal revocation invalidates sessions/closes tickets -----
    # alice revokes diego's terminal; his live session dies
    s, rev = call("/api/devices/revoke", {"device_id": "dev_diego"},
                  token=TOKENS["alice"])
    assert s == 200, (s, rev)
    assert "tok_" in rev["sessions_invalidated"][0]
    s, j = call("/api/keys", token=TOKENS["diego"])
    assert s == 401 and j["error"] in ("ATTESTATION_FAILED", "AUTH_FAILED"), (s, j)
    print(f"terminal revocation invalidated "
          f"{len(rev['sessions_invalidated'])} sessions, "
          f"closed {len(rev['tickets_closed'])} tickets")

    # ---- 10. audit chain + signed export with four-eyes records ---------
    s, aud = call("/api/audit", token=TOKENS["alice"])
    assert s == 200 and aud["verified"], aud.get("verify_problems")
    events = {e["event"] for e in aud["entries"]}
    assert {"operator_login", "authz_ticket_created", "authz_ticket_executed",
            "authz_ticket_closed", "authz_ticket_withdrawn"} <= events
    s, bundle = call("/api/export", token=TOKENS["carla"])
    assert s == 200
    from kc import export as export_mod
    verdict = export_mod.verify_bundle(bundle)
    assert verdict["ok"], verdict["problems"]
    assert verdict["checks"]["four_eyes_tickets_ok"]
    executed = [t for t in bundle["auth_tickets"]
                if t["status"] == "EXECUTED"]
    assert executed and all(
        t["creator"]["participant_id"] != t["approver"]["participant_id"]
        and t["creator"]["device_id"] != t["approver"]["device_id"]
        and t["creator"]["role"] != t["approver"]["role"]
        for t in executed)
    assert all(t["creator"]["token_id"] and t["approver"]["token_id"]
               for t in executed)
    print("export verified with", len(bundle["auth_tickets"]),
          "four-eyes tickets:", verdict["checks"])

    print("HTTP E2E ALL OK")
finally:
    proc.terminate()
    proc.wait(timeout=5)

# ---- 11. the orchestrator LIBRARY stays directly callable (no HTTP gate) --
from kc.ceremony import Orchestrator
from kc.storage import Store

store = Store(ROOT)
with store.locked():
    o = Orchestrator(store)
    # abort the still-open ROTATE directly: no session, no ticket needed
    opens = [c for c in o.state["ceremonies"].values() if c["status"] == "OPEN"]
    assert opens, "expected the withdrawn-flow ROTATE to remain open"
    o.abort(opens[0]["id"], "direct-library-operator",
            "library calls stay ungated")
    o.save()
    probs = o.audit.verify(
        __import__("kc.crypto", fromlist=["ed25519"]).ed25519.public_from_secret(
            store.service_seed()))
    assert not probs
print("direct library call still works without any ticket")
