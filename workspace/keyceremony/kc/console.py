"""Console-side helpers that drive *device wallets* through a ceremony.

The orchestrator never sees share values for GENERATE/ROTATE. These helpers
model what each participant's attested device would do on its own: fetch the
sealed delivery, decrypt it, verify the share against the published Feldman
commitments, then sign a confirmation envelope back to the orchestrator.
"""

from __future__ import annotations

import os

from . import crypto
from .attestation import DeviceWallet
from .errors import PolicyViolation


class DeviceContext:
    """Pairs an in-process wallet with the live ceremony view."""

    def __init__(self, wallet: DeviceWallet):
        self.wallet = wallet

    # ---- stage 1: attest -------------------------------------------------
    def attest(self, orch, ceremony_id: str,
               tamper_measurement: bytes | None = None) -> dict:
        ch = orch.challenge(ceremony_id, self.wallet.device_id)
        quote = self.wallet.quote(
            crypto.b64d(ch["challenge"]),
            live_measurement=tamper_measurement,
            now=orch.clock())
        env = self.wallet.sign_action(
            ceremony_id, "OPEN", "SUBMIT_ATTESTATION",
            {"quote": quote}, _nonce())
        return orch.submit_attestation(env)

    # ---- stage 2: receive + verify share ---------------------------------
    def receive_share(self, orch, ceremony_id: str) -> dict:
        c = orch.public_ceremony(ceremony_id)
        dlv = orch.fetch_delivery(ceremony_id, self.wallet.device_id)
        context = crypto.b64d(dlv["context"])
        self.wallet.inbox[dlv["delivery_id"]] = dlv["envelope"]
        value = self.wallet.open_delivery(dlv["delivery_id"], context)
        commits = [int(x) for x in (c["commitments"] or [])]
        ok = crypto.Dealer.verify_share(dlv["index"], value, commits)
        # stash the share on the device (in an HSM this never leaves hardware)
        self.wallet.inbox["share:" + ceremony_id] = {
            "index": dlv["index"], "value": str(value), "vss_ok": ok,
        }
        if not ok:
            raise PolicyViolation(
                f"{self.wallet.device_id}: share failed VSS verification")
        return {"delivery_id": dlv["delivery_id"], "index": dlv["index"],
                "vss_ok": ok}

    def held_share(self, ceremony_id: str) -> tuple[int, int]:
        rec = self.wallet.inbox["share:" + ceremony_id]
        return int(rec["index"]), int(rec["value"])

    # ---- stage 3: confirm -------------------------------------------------
    def confirm(self, orch, ceremony_id: str, note: str = "") -> dict:
        c = orch.public_ceremony(ceremony_id)
        kind = c["kind"]
        payload: dict = {"note": note}
        if kind != "DESTROY":
            rec = self.wallet.inbox.get("share:" + ceremony_id)
            if rec is None:
                raise PolicyViolation("device holds no share for this ceremony")
            dlv_id = next(
                (d["delivery_id"] for d in c["deliveries"]
                 if d["device_id"] == self.wallet.device_id), None)
            payload.update({
                "delivery_id": dlv_id,
                "index": int(rec["index"]),
                "vss_ok": bool(rec["vss_ok"]),
            })
        env = self.wallet.sign_action(
            ceremony_id,
            "DELIVERED" if kind != "DESTROY" else "CONFIRMED",
            "CONFIRM", payload, _nonce())
        return orch.submit_confirmation(env)

    # ---- BACKUP: submit surviving share ----------------------------------
    def submit_recovery_share(self, orch, ceremony_id: str,
                              source_ceremony_id: str | None = None) -> dict:
        src = source_ceremony_id
        if src is None:
            # most recent share held by this wallet
            keys = [k[len("share:"):] for k in self.wallet.inbox
                    if k.startswith("share:")]
            if not keys:
                raise PolicyViolation("device holds no share to recover from")
            src = sorted(keys)[-1]
        rec = self.wallet.inbox.get("share:" + src)
        if rec is None:
            raise PolicyViolation(f"no share on device for source {src}")
        index, value = int(rec["index"]), int(rec["value"])
        env = self.wallet.sign_action(
            ceremony_id, "DELIVERED", "SUBMIT_SHARE",
            {"device_id": self.wallet.device_id,
             "index": index, "share": str(value)}, _nonce())
        return orch.submit_share(env)


def _nonce() -> str:
    return "n_" + os.urandom(12).hex()
