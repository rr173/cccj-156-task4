"""End-to-end smoke: enroll fixed roles, run a GENERATE ceremony, sign/verify."""
import os, shutil, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import Orchestrator, Store, policy as P
from kc.attestation import provision_device
from kc.console import DeviceContext

ROOT = "/tmp/kc-smoke"
shutil.rmtree(ROOT, ignore_errors=True)
store = Store(ROOT)

with store.locked() as s:
    orch = Orchestrator(s)

    # 1. fixed participants + devices
    specs = [
        ("alice", "Alice (Security Officer)", P.ROOT_OWNER),
        ("bruno", "Bruno (HSM Steward)", P.KEY_STEWARD),
        ("carla", "Carla (Independent Witness)", P.WITNESS_SHAREHOLDER),
        ("diego", "Diego (Enclave Operator)", P.ENCLAVE_OPERATOR),
    ]
    wallets = {}
    slot_specs = []
    for pid, name, role in specs:
        orch.enroll_participant(pid, name, role)
        w = provision_device("dev_" + pid, name)
        wallets[pid] = w
        orch.bind_device(pid, w, label=role)
        slot_specs.append((pid, role, w.device_id))

    p = orch.create_policy("pol-root-v1", "Root key policy v1", 3, slot_specs)
    print("policy:", p["policy_id"], "threshold", p["threshold"])

    # 2. GENERATE ceremony
    pub = orch.public_ceremony(
        orch.open_ceremony(P.GENERATE, "pol-root-v1", "root-signing", "alice")["id"])
    cid = pub["id"]
    print("opened", cid, pub["stage"])

    ctxs = {pid: DeviceContext(w) for pid, w in wallets.items()}

    # everyone attests
    for pid, ctx in ctxs.items():
        view = ctx.attest(orch, cid)
    print("after attest:", view["stage"])

    # fetch+verify shares, then confirm (threshold 3)
    for pid, ctx in ctxs.items():
        r = ctx.receive_share(orch, cid)
        print(pid, "delivery", r["delivery_id"][:12], "index", r["index"], "vss", r["vss_ok"])

    # only 3 confirm: owner alice + steward bruno + witness carla
    view = None
    for pid in ("alice", "bruno", "carla"):
        view = ctxs[pid].confirm(orch, cid, note="share verified")
    print("after 3 confirmations:", view["stage"], "confirmed:", view["confirmations"])

    # commit
    done = orch.commit(cid, "alice")
    print("committed:", done["result"])

    # 3. sign with ACTIVE key, verify
    msg = b"hello root ceremony"
    res = orch.sign("root-signing", msg)
    print("signed by", res["version_id"][:14], res["status"])
    v = orch.verify("root-signing", msg, res["sig"])
    print("verify:", v)
    assert v["valid"] and v["status"] == "ACTIVE"

    orch.save()

# 4. reopen store, verify audit chain
with store.locked() as s:
    from kc.ed25519 import public_from_secret
    orch2 = Orchestrator(s)
    probs = orch2.audit.verify(public_from_secret(store.service_seed()))
    print("audit problems:", probs)
    assert not probs
    v2 = orch2.verify("root-signing", msg, res["sig"])
    print("verify after restart:", v2["valid"], v2["status"])

print("SMOKE OK")
