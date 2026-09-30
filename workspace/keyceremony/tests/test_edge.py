"""Additional security/edge tests."""
import os
import shutil
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import policy as P
from kc import crypto
from kc.attestation import provision_device
from kc.ceremony import Orchestrator
from kc.console import DeviceContext
from kc.errors import (AttestationError, ConflictState, PolicyViolation,
                       RaceLost)
from kc.storage import Store


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def make_world(root, clock, threshold=3, purposes=("root-signing",)):
    shutil.rmtree(root, ignore_errors=True)
    store = Store(root)
    people = [("alice", "A", P.ROOT_OWNER), ("bruno", "B", P.KEY_STEWARD),
              ("carla", "C", P.WITNESS_SHAREHOLDER), ("diego", "D", P.ENCLAVE_OPERATOR)]
    wallets = {}
    with store.locked():
        o = Orchestrator(store, clock=clock)
        slots = []
        for pid, name, role in people:
            o.enroll_participant(pid, name, role)
            w = provision_device("dev_" + pid, name)
            wallets[pid] = w
            o.bind_device(pid, w, role)
            slots.append((pid, role, w.device_id))
        o.create_policy("p1", "p", threshold, slots, purposes=purposes)
        o.save()
    return store, o, wallets


class TestTimeout(unittest.TestCase):
    def test_expired_ceremony_auto_aborts(self):
        clk = Clock()
        store, o, ws = make_world("/tmp/kc-edge-time", clk)
        with store.locked():
            cid = o.open_ceremony(P.GENERATE, "p1", "root-signing", "alice")["id"]
            clk.advance(1801)  # past ceremony_timeout_seconds
            with self.assertRaises(ConflictState):
                DeviceContext(ws["alice"]).attest(o, cid)
            c = o.public_ceremony(cid)
            self.assertEqual(c["status"], "ABORTED")
            self.assertIn("timed out", c["abort"]["reason"])
            events = [e["event"] for e in o.audit.entries]
            self.assertIn("ceremony_aborted", events)


class TestVSSFailure(unittest.TestCase):
    def test_device_reporting_vss_failure_cannot_confirm(self):
        clk = Clock()
        store, o, ws = make_world("/tmp/kc-edge-vss", clk)
        with store.locked():
            cid = o.open_ceremony(P.GENERATE, "p1", "root-signing", "alice")["id"]
            for w in ws.values():
                DeviceContext(w).attest(o, cid)
            for w in ws.values():
                DeviceContext(w).receive_share(o, cid)
            # corrupt carla's stored share -> she must refuse to confirm
            rec = ws["carla"].inbox["share:" + cid]
            rec["vss_ok"] = False
            with self.assertRaises(PolicyViolation):
                DeviceContext(ws["carla"]).confirm(o, cid)

    def test_wrong_delivery_reference_rejected(self):
        clk = Clock()
        store, o, ws = make_world("/tmp/kc-edge-dlv", clk)
        with store.locked():
            cid = o.open_ceremony(P.GENERATE, "p1", "root-signing", "alice")["id"]
            for w in ws.values():
                DeviceContext(w).attest(o, cid)
            for w in ws.values():
                DeviceContext(w).receive_share(o, cid)
            env = ws["alice"].sign_action(
                cid, "DELIVERED", "CONFIRM",
                {"delivery_id": "dlv_fake", "index": 1, "vss_ok": True,
                 "note": ""}, "n-fake-1")
            with self.assertRaises(Exception):
                o.submit_confirmation(env)


class TestRevokedDevice(unittest.TestCase):
    def test_revoked_device_cannot_act(self):
        clk = Clock()
        store, o, ws = make_world("/tmp/kc-edge-rev", clk)
        with store.locked():
            o.state["devices"]["dev_diego"]["revoked"] = True
            cid = o.open_ceremony(P.GENERATE, "p1", "root-signing", "alice")["id"]
            with self.assertRaises(AttestationError):
                DeviceContext(ws["diego"]).attest(o, cid)


class TestPolicyGuards(unittest.TestCase):
    def test_threshold_one_rejected(self):
        clk = Clock()
        store = Store("/tmp/kc-edge-t1")
        shutil.rmtree("/tmp/kc-edge-t1", ignore_errors=True)
        with store.locked():
            o = Orchestrator(store, clock=clk)
            o.enroll_participant("a", "A", P.ROOT_OWNER)
            o.enroll_participant("b", "B", P.WITNESS_SHAREHOLDER)
            o.enroll_participant("c", "C", P.WITNESS_SHAREHOLDER)
            wa = provision_device("d1", "A"); wb = provision_device("d2", "B")
            wc = provision_device("d3", "C")
            o.bind_device("a", wa); o.bind_device("b", wb); o.bind_device("c", wc)
            with self.assertRaises(PolicyViolation):
                o.create_policy("p", "p", 1,
                    [("a", P.ROOT_OWNER, "d1"), ("b", P.WITNESS_SHAREHOLDER, "d2"),
                     ("c", P.WITNESS_SHAREHOLDER, "d3")])

    def test_missing_owner_role_rejected(self):
        clk = Clock()
        store = Store("/tmp/kc-edge-noowner")
        shutil.rmtree("/tmp/kc-edge-noowner", ignore_errors=True)
        with store.locked():
            o = Orchestrator(store, clock=clk)
            ids = []
            for i, role in enumerate([P.KEY_STEWARD, P.WITNESS_SHAREHOLDER,
                                      P.ENCLAVE_OPERATOR]):
                pid = f"p{i}"
                o.enroll_participant(pid, pid, role)
                w = provision_device(f"d{i}", pid)
                o.bind_device(pid, w)
                ids.append((pid, role, f"d{i}"))
            with self.assertRaises(PolicyViolation):
                o.create_policy("p", "p", 2, ids)


class TestMultipurposeAndLocking(unittest.TestCase):
    def test_two_purposes_coexist_with_independent_actives(self):
        clk = Clock()
        store, o, ws = make_world(
            "/tmp/kc-edge-multi", clk,
            purposes=("root-signing", "sealing"))

        def generate(purpose):
            cid = o.open_ceremony(P.GENERATE, "p1", purpose, "alice")["id"]
            for w in ws.values():
                DeviceContext(w).attest(o, cid)
            for w in ws.values():
                DeviceContext(w).receive_share(o, cid)
            for pid in ("alice", "bruno", "carla"):
                DeviceContext(ws[pid]).confirm(o, cid)
            o.commit(cid, "alice")

        with store.locked():
            generate("root-signing")
            generate("sealing")
            sigs = {}
            for purpose in ("root-signing", "sealing"):
                r = o.sign(purpose, b"m-" + purpose.encode())
                sigs[purpose] = r
                self.assertEqual(r["status"], "ACTIVE")
            # cross-purpose verification fails (different keys)
            other = o.verify("sealing", b"m-root-signing", sigs["root-signing"]["sig"])
            self.assertFalse(other["valid"])
            own = o.verify("sealing", b"m-sealing", sigs["sealing"]["sig"])
            self.assertTrue(own["valid"])

    def test_concurrent_threads_never_produce_two_active(self):
        """Two threads hammering open+rotate on the same purpose must never
        observe two ACTIVE versions; lock serializes them."""
        clk = Clock()
        store, o, ws = make_world("/tmp/kc-edge-thr", clk)

        def generate(purpose):
            cid = o.open_ceremony(P.GENERATE, "p1", purpose, "alice")["id"]
            for w in ws.values():
                DeviceContext(w).attest(o, cid)
            for w in ws.values():
                DeviceContext(w).receive_share(o, cid)
            for pid in ("alice", "bruno", "carla"):
                DeviceContext(ws[pid]).confirm(o, cid)
            o.commit(cid, "alice")

        with store.locked():
            generate("root-signing")
            o.save()  # persist before other threads load fresh state

        errors = []
        contention = []

        def worker():
            try:
                with store.locked():
                    ox = Orchestrator(store, clock=clk)
                    cur = ox.dir.active_id("root-signing")
                    try:
                        cid = ox.open_ceremony(
                            P.ROTATE, "p1", "root-signing", "alice")["id"]
                    except ConflictState:
                        contention.append("open conflict")
                        return  # another open rotation: expected
                    for w in ws.values():
                        DeviceContext(w).attest(ox, cid)
                    for w in ws.values():
                        DeviceContext(w).receive_share(ox, cid)
                    for pid in ("alice", "bruno", "carla"):
                        DeviceContext(ws[pid]).confirm(ox, cid)
                    ox.commit(cid, "alice")
                    try:
                        ox.publish_rotation(cid, "alice", expected_active=cur)
                    except RaceLost:
                        contention.append("publish race lost")
                    ox.save()
            except (ConflictState, RaceLost, PolicyViolation) as e:
                contention.append(repr(e))
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], [repr(e) for e in errors])
        with store.locked():
            ox = Orchestrator(store, clock=clk)
            actives = [k for k in ox.dir.versions_for_purpose("root-signing")
                       if k["status"] == "ACTIVE"]
            self.assertEqual(len(actives), 1)
            # at most one RETIRING (no overlapping handover windows)
            retiring = [k for k in ox.dir.versions_for_purpose("root-signing")
                        if k["status"] == "RETIRING"]
            self.assertLessEqual(len(retiring), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
