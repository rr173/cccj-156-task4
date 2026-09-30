"""Simulated device fleet: agents that hold wallets and drive ceremonies.

In a real deployment every participant runs their own agent against their
HSM. For this system a single `Fleet` keeps the wallets in a directory (one
0600 JSON file per device) and offers the exact operations a device agent
performs: attest, receive, confirm, submit recovery shares. Wallets never
cross into orchestrator state.
"""

from __future__ import annotations

import os

from .attestation import DeviceWallet, provision_device
from .console import DeviceContext


class Fleet:
    def __init__(self, wallet_dir: str):
        self.dir = wallet_dir
        os.makedirs(wallet_dir, exist_ok=True)

    def _path(self, device_id: str) -> str:
        return os.path.join(self.dir, device_id + ".wallet.json")

    def provision(self, device_id: str, label: str) -> DeviceWallet:
        w = provision_device(device_id, label)
        w.save(self._path(device_id))
        return w

    def get(self, device_id: str) -> DeviceWallet:
        return DeviceWallet.load(self._path(device_id))

    def save(self, w: DeviceWallet):
        w.save(self._path(w.device_id))

    def has(self, device_id: str) -> bool:
        return os.path.exists(self._path(device_id))

    # ---- agent operations (one ceremony step each) -----------------------
    def attest(self, orch, ceremony_id: str, device_id: str,
               bad_measurement: bool = False):
        w = self.get(device_id)
        ctx = DeviceContext(w)
        tamper = os.urandom(32) if bad_measurement else None
        view = ctx.attest(orch, ceremony_id, tamper_measurement=tamper)
        return view

    def receive(self, orch, ceremony_id: str, device_id: str):
        w = self.get(device_id)
        ctx = DeviceContext(w)
        r = ctx.receive_share(orch, ceremony_id)
        self.save(w)
        return r

    def confirm(self, orch, ceremony_id: str, device_id: str, note: str = ""):
        w = self.get(device_id)
        ctx = DeviceContext(w)
        view = ctx.confirm(orch, ceremony_id, note=note)
        self.save(w)
        return view

    def submit_recovery(self, orch, ceremony_id: str, device_id: str,
                        source_ceremony_id: str | None = None):
        w = self.get(device_id)
        ctx = DeviceContext(w)
        return ctx.submit_recovery_share(
            orch, ceremony_id, source_ceremony_id=source_ceremony_id)
