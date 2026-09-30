"""Bootstrap a demo environment: fixed roles, devices, policy.

Usage: python -m kc.bootstrap --root ./kc-data
"""

from __future__ import annotations

import argparse
import os

from . import policy as P
from .attestation import provision_device
from .ceremony import Orchestrator
from .storage import Store

ROSTER = [
    ("alice", "Alice — Security Officer", P.ROOT_OWNER),
    ("bruno", "Bruno — HSM Steward", P.KEY_STEWARD),
    ("carla", "Carla — Independent Witness", P.WITNESS_SHAREHOLDER),
    ("diego", "Diego — Enclave Operator", P.ENCLAVE_OPERATOR),
]


def bootstrap(root: str, threshold: int = 3, policy_id: str = "pol-root-v1",
              purposes=("root-signing",)):
    store = Store(root)
    wallet_dir = f"{root}/wallets"
    os.makedirs(wallet_dir, exist_ok=True)
    with store.locked():
        orch = Orchestrator(store)
        slots = []
        for pid, name, role in ROSTER:
            try:
                orch.enroll_participant(pid, name, role)
            except Exception:
                pass
            did = "dev_" + pid
            wallet_path = f"{wallet_dir}/{did}.wallet.json"
            if os.path.exists(wallet_path):
                from .attestation import DeviceWallet

                w = DeviceWallet.load(wallet_path)
            else:
                w = provision_device(did, name)
                w.save(wallet_path)
            if did not in orch.state["devices"]:
                orch.bind_device(pid, w, label=role)
            slots.append((pid, role, did))
        if policy_id not in orch.state["policies"]:
            orch.create_policy(policy_id, "Bootstrapped root key policy",
                               threshold, slots, purposes=purposes)
        orch.save()
    return {
        "root": root,
        "policy_id": policy_id,
        "threshold": threshold,
        "participants": [{"participant_id": pid, "device_id": "dev_" + pid,
                          "role": role} for pid, _, role in ROSTER],
        "purposes": list(purposes),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--threshold", type=int, default=3)
    a = ap.parse_args(argv)
    info = bootstrap(a.root, a.threshold)
    print("bootstrapped:")
    for p in info["participants"]:
        print(f"  {p['participant_id']:<8} {p['role']:<24} {p['device_id']}")
    print(f"policy {info['policy_id']} threshold={info['threshold']}")


if __name__ == "__main__":
    main()
