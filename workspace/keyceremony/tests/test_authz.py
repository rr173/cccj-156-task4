"""Tests for terminal-attested operator sessions and four-eyes authorization.

Covers:
  * login token binding (person/duty/terminal/attestation freshness),
    challenge replay, bad measurement, revoked terminal, session expiry;
  * duty-based read/action gating;
  * ticket creation freeze + digest, duplicate resubmission idempotency,
    withdrawal;
  * four-eyes enforcement (different person, different terminal,
    complementary duty), deadline expiry, payload drift, target change;
  * at-most-once execution under concurrency, no half-applied state;
  * the four protected operations end to end (policy change, abort,
    publish, purge);
  * export bundle records parties/token ids/digest/decision/execution and
    offline verification flags tampering of those records.
"""

import json
import os
import shutil
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import policy as P
from kc import crypto, export as export_mod
from kc.attestation import provision_device
from kc.authz import (
    Authz, ABORT_ACTIVE, CLOSED, EXECUTED, POLICY_CHANGE,
    PUBLISH_GENERATION, PURGE_RETIRED, WITHDRAWN,
    R_DUTY_CONFLICT, R_PAYLOAD_DRIFT, R_TARGET_CHANGED, R_SESSION_EXPIRED,
    R_DEADLINE, R_TERMINAL_REVOKED, ticket_digest,
)
from kc.ceremony import Orchestrator
from kc.console import DeviceContext
from kc.errors import (
    AttestationError, AuthenticationError, ComplementaryDutyConflict,
    Forbidden, PayloadDrift, PolicyViolation,
    TargetStateChanged, TicketClosed,
)
from kc.sessions import SessionManager
from kc.storage import Store

PEOPLE = [
    ("alice", "Alice Owner", P.ROOT_OWNER),
    ("bruno", "Bruno Steward", P.KEY_STEWARD),
    ("carla", "Carla Witness", P.WITNESS_SHAREHOLDER),
    ("diego", "Diego Op", P.ENCLAVE_OPERATOR),
]


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class AuthzWorld:
    """Store + 4 rostered people with wallets, plus session/authz managers."""

    def __init__(self, root="/tmp/kc-authz-world", ttl=3600, ticket_ttl=600,
                 clock=None):
        shutil.rmtree(root, ignore_errors=True)
        self.root = root
        self.clock = clock or Clock()
        self.store = Store(root)
        self.wallets = {}
        with self.store.locked():
            self.o = Orchestrator(self.store, clock=self.clock)
            slots = []
            for pid, name, role in PEOPLE:
                self.o.enroll_participant(pid, name, role)
                w = provision_device("dev_" + pid, name)
                self.wallets[pid] = w
                self.o.bind_device(pid, w, label=role)
                slots.append((pid, role, w.device_id))
            self.o.create_policy("pol-root-v1", "root policy", 3, slots)
            self.sm = SessionManager(self.o.state, self.o.audit,
                                     clock=self.clock, ttl_seconds=ttl)
            self.az = Authz(self.o.state, self.o.audit, self.sm,
                            clock=self.clock, ttl_seconds=ticket_ttl)
            self.o.save()
        self.tokens = {}

    def save(self):
        self.o.save()

    def reopen(self, ttl=3600, ticket_ttl=600):
        with self.store.locked():
            self.o = Orchestrator(self.store, clock=self.clock)
            self.sm = SessionManager(self.o.state, self.o.audit,
                                     clock=self.clock, ttl_seconds=ttl)
            self.az = Authz(self.o.state, self.o.audit, self.sm,
                            clock=self.clock, ttl_seconds=ticket_ttl)

    def _quote(self, pid, bad=False, challenge=None):
        w = self.wallets[pid]
        ch = challenge
        if ch is None:
            did = w.device_id
            ch = crypto.b64d(self.sm.login_challenge(did)["challenge"])
        live = os.urandom(32) if bad else None
        return w.quote(ch, live_measurement=live, now=self.clock())

    def login(self, pid, bad=False, ttl=None):
        did = self.wallets[pid].device_id
        ch_b64 = self.sm.login_challenge(did)["challenge"]
        quote = self._quote(pid, bad=bad,
                            challenge=crypto.b64d(ch_b64))
        rec = self.sm.login(did, ch_b64, quote, ttl_seconds=ttl)
        self.tokens[pid] = rec["token"]
        return rec

    def session(self, pid):
        return self.sm.validate(self.tokens[pid])

    # -- full ceremony helpers (driven through the library directly) ------
    def generate(self, purpose="root-signing"):
        cid = self.o.open_ceremony(P.GENERATE, "pol-root-v1", purpose,
                                   "alice")["id"]
        for pid, _, _ in PEOPLE:
            DeviceContext(self.wallets[pid]).attest(self.o, cid)
        for pid, _, _ in PEOPLE:
            DeviceContext(self.wallets[pid]).receive_share(self.o, cid)
        for pid in ("alice", "bruno", "carla"):
            DeviceContext(self.wallets[pid]).confirm(self.o, cid)
        self.o.commit(cid, "alice")
        return cid

    def rotate_done(self, purpose="root-signing"):
        cid = self.o.open_ceremony(P.ROTATE, "pol-root-v1", purpose,
                                   "diego")["id"]
        for pid, _, _ in PEOPLE:
            DeviceContext(self.wallets[pid]).attest(self.o, cid)
        for pid, _, _ in PEOPLE:
            DeviceContext(self.wallets[pid]).receive_share(self.o, cid)
        for pid in ("alice", "bruno", "carla"):
            DeviceContext(self.wallets[pid]).confirm(self.o, cid)
        self.o.commit(cid, "diego")
        return cid

    def destroy_opened(self, retiring_id, purpose="root-signing"):
        return self.o.open_ceremony(
            P.DESTROY, "pol-root-v1", purpose, "bruno",
            target_version=retiring_id)["id"]

    def attest_confirm_destroy(self, cid):
        for pid, _, _ in PEOPLE:
            DeviceContext(self.wallets[pid]).attest(self.o, cid)
        for pid in ("alice", "bruno", "carla"):
            DeviceContext(self.wallets[pid]).confirm(self.o, cid)


class TestLoginBinding(unittest.TestCase):
    def setUp(self):
        self.w = AuthzWorld("/tmp/kc-authz-login")

    def test_token_binds_person_duty_terminal_and_freshness(self):
        with self.w.store.locked():
            rec = self.w.login("alice")
            got = self.w.session("alice")
            self.assertEqual(got["participant_id"], "alice")
            self.assertEqual(got["role"], P.ROOT_OWNER)
            self.assertEqual(got["device_id"], "dev_alice")
            self.assertAlmostEqual(
                got["expires_at"] - got["created_at"], 3600, places=2)
            # measurement is bound to the registered terminal measurement
            self.assertEqual(got["measurement"],
                             crypto.b64e(self.w.wallets["alice"].measurement))
            self.assertTrue(rec["token"].startswith("stk_"))
            self.assertNotIn(rec["token"], json.dumps(
                self.w.sm.list_sessions()))  # raw token never stored

    def test_challenge_single_use_and_unknown_token_rejected(self):
        with self.w.store.locked():
            self.w.login("alice")
            tok = self.w.tokens["alice"]
            with self.assertRaises(AuthenticationError):
                self.w.sm.validate("stk_forged" + "A" * 40)
            # challenge already consumed -> cannot replay the same quote
            ch = self.w.o.state["login_challenges"]["dev_alice"]["challenge"]
            quote = self.w._quote("alice", challenge=crypto.b64d(ch))
            with self.assertRaises(AuthenticationError):
                self.w.sm.login("dev_alice", ch, quote)

    def test_bad_measurement_login_rejected(self):
        with self.w.store.locked():
            with self.assertRaises(AttestationError):
                self.w.login("alice", bad=True)

    def test_revoked_terminal_cannot_login_and_kills_session(self):
        with self.w.store.locked():
            self.w.login("alice")
            self.w.o.state["devices"]["dev_alice"]["revoked"] = True
            with self.assertRaises(AttestationError):
                self.w.session("alice")
            with self.assertRaises(AttestationError):
                self.w.login("alice")

    def test_session_expiry_closes_binding(self):
        w = AuthzWorld("/tmp/kc-authz-exp", ttl=10)
        with w.store.locked():
            w.login("alice")
            w.clock.advance(11)
            with self.assertRaises(AuthenticationError):
                w.session("alice")

    def test_relogin_supersedes_old_token_but_ticket_continues(self):
        with self.w.store.locked():
            first = self.w.login("alice")
            self.w.clock.advance(1)
            second = self.w.login("alice")  # same terminal, fresh attestation
            self.assertNotEqual(first["token"], second["token"])
            with self.assertRaises(AuthenticationError):
                self.w.sm.validate(first["token"])
            # new token works
            self.assertEqual(self.w.session("alice")["token_id"],
                             second["token_id"])


class TestDutyGating(unittest.TestCase):
    def setUp(self):
        self.w = AuthzWorld("/tmp/kc-authz-duty")

    def test_read_scopes_per_duty(self):
        with self.w.store.locked():
            self.w.login("carla")  # witness
            sess = self.w.session("carla")
            self.assertTrue(Authz.can_read(sess["role"], "audit"))
            self.assertTrue(Authz.can_read(sess["role"], "export"))
            self.w.login("diego")  # operator
            sess = self.w.session("diego")
            self.assertFalse(Authz.can_read(sess["role"], "audit"))
            self.assertFalse(Authz.can(sess["role"], "participant:enroll"))
            with self.assertRaises(Forbidden):
                Authz.require_cap(sess, "participant:enroll")

    def test_witness_cannot_open_ceremony(self):
        with self.w.store.locked():
            self.w.login("carla")
            with self.assertRaises(Forbidden):
                Authz.require_cap(self.w.session("carla"), "ceremony:open")


class TestTicketCreation(unittest.TestCase):
    def setUp(self):
        self.w = AuthzWorld("/tmp/kc-authz-create")

    def _policy_payload(self, pid="pol-root-v2"):
        slots = [["alice", "ROOT_OWNER", "dev_alice"],
                 ["bruno", "KEY_STEWARD", "dev_bruno"],
                 ["carla", "WITNESS_SHAREHOLDER", "dev_carla"],
                 ["diego", "ENCLAVE_OPERATOR", "dev_diego"]]
        return {"policy_id": pid, "label": "v2", "threshold": 3,
                "slots": slots}

    def test_only_creator_duty_may_initiate(self):
        with self.w.store.locked():
            self.w.login("diego")  # operator may not change rules
            with self.assertRaises(Forbidden):
                self.w.az.create_ticket(
                    POLICY_CHANGE, self._policy_payload(),
                    self.w.session("diego"))

    def test_frozen_digest_is_canonical_and_key_order_insensitive(self):
        with self.w.store.locked():
            self.w.login("alice")
            p1 = self._policy_payload()
            p2 = json.loads(json.dumps(p1))  # same content, reordered later
            key = list(p2.keys())
            # shuffle key order in serialized input by building a dict reversed
            p2 = {k: p1[k] for k in reversed(list(p1.keys()))}
            self.assertEqual(ticket_digest(POLICY_CHANGE, p1),
                             ticket_digest(POLICY_CHANGE, p2))
            t, dup = self.w.az.create_ticket(
                POLICY_CHANGE, p1, self.w.session("alice"))
            self.assertFalse(dup)
            self.assertEqual(t["digest"],
                             ticket_digest(POLICY_CHANGE, t["payload"]))

    def test_duplicate_submission_returns_original_ticket(self):
        with self.w.store.locked():
            self.w.login("alice")
            t1, d1 = self.w.az.create_ticket(
                POLICY_CHANGE, self._policy_payload(),
                self.w.session("alice"))
            t2, d2 = self.w.az.create_ticket(
                POLICY_CHANGE, self._policy_payload(),
                self.w.session("alice"))
            self.assertFalse(d1)
            self.assertTrue(d2)
            self.assertEqual(t1["id"], t2["id"])

    def test_different_payload_gets_distinct_ticket(self):
        with self.w.store.locked():
            self.w.login("alice")
            t1, _ = self.w.az.create_ticket(
                POLICY_CHANGE, self._policy_payload("pol-a"),
                self.w.session("alice"))
            t2, dup = self.w.az.create_ticket(
                POLICY_CHANGE, self._policy_payload("pol-b"),
                self.w.session("alice"))
            self.assertFalse(dup)
            self.assertNotEqual(t1["id"], t2["id"])


class TestFourEyesApproval(unittest.TestCase):
    def setUp(self):
        self.w = AuthzWorld("/tmp/kc-authz-4eyes")

    def _make_policy_ticket(self):
        self.w.login("alice")
        payload = {"policy_id": "pol-root-v2", "label": "v2", "threshold": 3,
                   "slots": [["alice", "ROOT_OWNER", "dev_alice"],
                             ["bruno", "KEY_STEWARD", "dev_bruno"],
                             ["carla", "WITNESS_SHAREHOLDER", "dev_carla"],
                             ["diego", "ENCLAVE_OPERATOR", "dev_diego"]]}
        t, _ = self.w.az.create_ticket(
            POLICY_CHANGE, payload, self.w.session("alice"))
        return t["id"], payload

    def _policy_executor(self, payload):
        return lambda p: self.w.o.create_policy(
            p["policy_id"], p["label"], int(p["threshold"]),
            [tuple(s) for s in p["slots"]])

    def test_same_person_cannot_approve(self):
        with self.w.store.locked():
            tid, payload = self._make_policy_ticket()
            with self.assertRaises(ComplementaryDutyConflict):
                self.w.az.approve(tid, self.w.tokens["alice"],
                                  executors={POLICY_CHANGE:
                                             self._policy_executor(payload)})
            t = self.w.az.get_public(tid)
            self.assertEqual(t["status"], CLOSED)
            self.assertEqual(t["closed_reason"], R_DUTY_CONFLICT)

    def test_wrong_duty_cannot_approve(self):
        with self.w.store.locked():
            tid, payload = self._make_policy_ticket()
            self.w.login("bruno")  # steward cannot witness rule changes
            with self.assertRaises(ComplementaryDutyConflict):
                self.w.az.approve(tid, self.w.tokens["bruno"],
                                  executors={POLICY_CHANGE:
                                             self._policy_executor(payload)})
            self.assertEqual(self.w.az.get_public(tid)["closed_reason"],
                             R_DUTY_CONFLICT)

    def test_complementary_duty_different_terminal_executes_once(self):
        with self.w.store.locked():
            tid, payload = self._make_policy_ticket()
            self.w.login("carla")  # independent witness, other terminal
            out = self.w.az.approve(
                tid, self.w.tokens["carla"],
                executors={POLICY_CHANGE: self._policy_executor(payload)})
            self.assertEqual(out["status"], EXECUTED)
            self.assertIn("pol-root-v2", self.w.o.state["policies"])
            self.assertIsNotNone(out["execution"]["result"])
            # second approval is rejected (already executed), not re-run
            with self.assertRaises(TicketClosed):
                self.w.az.approve(
                    tid, self.w.tokens["carla"],
                    executors={POLICY_CHANGE: self._policy_executor(payload)})

    def test_payload_drift_closes_ticket_no_execution(self):
        with self.w.store.locked():
            tid, payload = self._make_policy_ticket()
            self.w.login("carla")
            drifted = dict(payload)
            drifted["threshold"] = 2
            with self.assertRaises(PayloadDrift):
                self.w.az.approve(
                    tid, self.w.tokens["carla"],
                    executors={POLICY_CHANGE: self._policy_executor(drifted)},
                    presented_payload=drifted)
            t = self.w.az.get_public(tid)
            self.assertEqual(t["status"], CLOSED)
            self.assertEqual(t["closed_reason"], R_PAYLOAD_DRIFT)
            self.assertNotIn("pol-root-v2", self.w.o.state["policies"])

    def test_deadline_expiry_closes_ticket(self):
        w = AuthzWorld("/tmp/kc-authz-dead", ticket_ttl=30)
        with w.store.locked():
            w.login("alice")
            payload = {"policy_id": "p2", "label": "x", "threshold": 3,
                       "slots": [["alice", "ROOT_OWNER", "dev_alice"],
                                 ["bruno", "KEY_STEWARD", "dev_bruno"],
                                 ["carla", "WITNESS_SHAREHOLDER", "dev_carla"],
                                 ["diego", "ENCLAVE_OPERATOR", "dev_diego"]]}
            _t, _ = w.az.create_ticket(POLICY_CHANGE, payload,
                                       w.session("alice"))
            tid = _t["id"]
            w.clock.advance(31)
            w.login("carla")
            with self.assertRaises(TicketClosed):
                w.az.approve(tid, w.tokens["carla"],
                             executors={POLICY_CHANGE: lambda p: None})
            self.assertEqual(w.az.get_public(tid)["closed_reason"], R_DEADLINE)
    def test_creator_token_dead_without_relogin_closes_ticket(self):
        w = AuthzWorld("/tmp/kc-authz-creatorexp", ttl=10)
        with w.store.locked():
            w.login("alice")
            payload = {"policy_id": "p2", "label": "x", "threshold": 3,
                       "slots": [["alice", "ROOT_OWNER", "dev_alice"],
                                 ["bruno", "KEY_STEWARD", "dev_bruno"],
                                 ["carla", "WITNESS_SHAREHOLDER", "dev_carla"],
                                 ["diego", "ENCLAVE_OPERATOR", "dev_diego"]]}
            _t, _ = w.az.create_ticket(POLICY_CHANGE, payload,
                                       w.session("alice"))
            tid = _t["id"]
            w.clock.advance(11)
            w.login("carla")
            with self.assertRaises(TicketClosed):
                w.az.approve(tid, w.tokens["carla"],
                             executors={POLICY_CHANGE: lambda p: None})
            self.assertEqual(w.az.get_public(tid)["closed_reason"],
                             R_SESSION_EXPIRED)

    def test_relogin_same_terminal_allows_continuation(self):
        w = AuthzWorld("/tmp/kc-authz-cont", ttl=10)
        with w.store.locked():
            w.login("alice")
            payload = {"policy_id": "p2", "label": "x", "threshold": 3,
                       "slots": [["alice", "ROOT_OWNER", "dev_alice"],
                                 ["bruno", "KEY_STEWARD", "dev_bruno"],
                                 ["carla", "WITNESS_SHAREHOLDER", "dev_carla"],
                                 ["diego", "ENCLAVE_OPERATOR", "dev_diego"]]}
            _t, _ = w.az.create_ticket(POLICY_CHANGE, payload,
                                       w.session("alice"))
            tid = _t["id"]
            w.clock.advance(11)
            w.login("alice")  # re-attest on the same terminal
            w.login("carla")
            out = w.az.approve(tid, w.tokens["carla"],
                               executors={POLICY_CHANGE:
                                          lambda p: w.o.create_policy(
                                              p["policy_id"], p["label"],
                                              int(p["threshold"]),
                                              [tuple(s) for s in p["slots"]])})
            self.assertEqual(out["status"], EXECUTED)

    def test_terminal_revocation_closes_open_ticket(self):
        with self.w.store.locked():
            tid, _ = self._make_policy_ticket()
            closed = self.w.az.close_for_terminal("dev_alice")
            self.assertEqual(closed, [tid])
            self.assertEqual(self.w.az.get_public(tid)["closed_reason"],
                             R_TERMINAL_REVOKED)

    def test_revoke_terminal_api_invalidates_session_and_pending_ticket(self):
        with self.w.store.locked():
            tid, _ = self._make_policy_ticket()
            killed = self.w.sm.revoke_terminal("dev_alice")
            closed = self.w.az.close_for_terminal("dev_alice")
            self.assertTrue(any(k for k in killed))
            self.assertEqual(closed, [tid])
            with self.assertRaises((AttestationError, AuthenticationError)):
                self.w.session("alice")
            self.assertEqual(self.w.az.get_public(tid)["status"], CLOSED)

    def test_withdraw_by_creator_then_resubmit_creates_new(self):
        with self.w.store.locked():
            tid, payload = self._make_policy_ticket()
            self.w.az.withdraw(tid, self.w.tokens["alice"])
            self.assertEqual(self.w.az.get_public(tid)["status"], WITHDRAWN)
            # bruno cannot withdraw alice's ticket
            t2, dup = self.w.az.create_ticket(
                POLICY_CHANGE, payload, self.w.session("alice"))
            self.assertFalse(dup)
            self.assertNotEqual(tid, t2["id"])

    def test_other_person_cannot_withdraw(self):
        with self.w.store.locked():
            tid, _ = self._make_policy_ticket()
            self.w.login("bruno")
            with self.assertRaises(Forbidden):
                self.w.az.withdraw(tid, self.w.tokens["bruno"])

    def test_executor_failure_closes_ticket_without_half_state(self):
        with self.w.store.locked():
            tid, payload = self._make_policy_ticket()
            self.w.login("carla")

            def boom(_p):
                raise PolicyViolation("simulated late validation failure")

            with self.assertRaises(PolicyViolation):
                self.w.az.approve(
                    tid, self.w.tokens["carla"],
                    executors={POLICY_CHANGE: boom})
            t = self.w.az.get_public(tid)
            self.assertEqual(t["status"], CLOSED)
            self.assertEqual(t["closed_reason"], "executor_error")
            # no dangling approval without execution; chain ends with closed
            types_ = [d["type"] for d in t["decision_chain"]]
            self.assertEqual(types_[-1], "closed")
            self.assertNotIn("approved", types_)
            self.assertIsNone(t["approver"])
            self.assertIsNone(t["execution"])
            # rule set untouched
            self.assertNotIn("pol-root-v2", self.w.o.state["policies"])


class TestProtectedOperations(unittest.TestCase):
    def test_publish_four_eyes_and_target_change_drift(self):
        w = AuthzWorld("/tmp/kc-authz-pub")
        with w.store.locked():
            w.generate()
            cid = w.rotate_done()
            old = w.o.dir.active_id("root-signing")
            # operator creates the ticket; owner must approve
            w.login("diego")
            payload = {"ceremony_id": cid, "expected_active": old}
            t, _ = w.az.create_ticket(PUBLISH_GENERATION, payload,
                                      w.session("diego"))
            # target moves before approval (simulate stale target): publish
            # via library is impossible without a STAGED conflict, so mutate
            # the frozen expectation instead -> preflight catches drift
            w.login("alice")
            drifted = {"ceremony_id": cid, "expected_active": "kv_other"}
            with self.assertRaises(PayloadDrift):
                w.az.approve(
                    t["id"], w.tokens["alice"],
                    executors={PUBLISH_GENERATION: lambda p:
                               w.o.publish_rotation(p["ceremony_id"], "alice",
                                                    p["expected_active"])},
                    presented_payload=drifted)
            self.assertEqual(w.az.get_public(t["id"])["closed_reason"],
                             R_PAYLOAD_DRIFT)

            # fresh ticket, real complementary approval executes the CAS
            t2, _ = w.az.create_ticket(PUBLISH_GENERATION, payload,
                                       w.session("diego"))
            out = w.az.approve(
                t2["id"], w.tokens["alice"],
                executors={PUBLISH_GENERATION: lambda p:
                           w.o.publish_rotation(p["ceremony_id"], "alice",
                                                p["expected_active"])},
                preflights={PUBLISH_GENERATION: _publish_preflight(w, payload)})
            self.assertEqual(out["status"], EXECUTED)
            self.assertEqual(w.o.dir.active("root-signing")["version"], 2)

            # a third approval attempt on an executed ticket is a no-go
            with self.assertRaises(TicketClosed):
                w.az.approve(
                    t2["id"], w.tokens["alice"],
                    executors={PUBLISH_GENERATION: lambda p:
                               w.o.publish_rotation(p["ceremony_id"], "alice",
                                                    p["expected_active"])})

    def test_publish_target_state_change_closes_without_effect(self):
        w = AuthzWorld("/tmp/kc-authz-tsc")
        with w.store.locked():
            w.generate()
            cid = w.rotate_done()
            old = w.o.dir.active_id("root-signing")
            w.login("diego")
            payload = {"ceremony_id": cid, "expected_active": old}
            t, _ = w.az.create_ticket(PUBLISH_GENERATION, payload,
                                      w.session("diego"))
            # state advanced out-of-band (library/direct path): published
            w.o.publish_rotation(cid, "direct-library-call", old)
            w.login("alice")

            def preflight(p):
                c = w.o.state["ceremonies"][p["ceremony_id"]]
                if c.get("published"):
                    raise TargetStateChanged("already published")

            with self.assertRaises(TargetStateChanged):
                w.az.approve(
                    t["id"], w.tokens["alice"],
                    executors={PUBLISH_GENERATION: lambda p:
                               w.o.publish_rotation(p["ceremony_id"], "alice",
                                                    p["expected_active"])},
                    preflights={PUBLISH_GENERATION: preflight})
            self.assertEqual(w.az.get_public(t["id"])["closed_reason"],
                             R_TARGET_CHANGED)
            # exactly one ACTIVE, and it's the library-published generation
            actives = [k for k in w.o.dir.versions_for_purpose("root-signing")
                       if k["status"] == "ACTIVE"]
            self.assertEqual(len(actives), 1)

    def test_abort_four_eyes(self):
        w = AuthzWorld("/tmp/kc-authz-abort")
        with w.store.locked():
            w.login("diego")
            cid = w.o.open_ceremony(P.GENERATE, "pol-root-v1", "root-signing",
                                    "diego")["id"]
            payload = {"ceremony_id": cid, "reason": "operator halt"}
            t, _ = w.az.create_ticket(ABORT_ACTIVE, payload,
                                      w.session("diego"))
            # operator cannot self-approve; witness is complementary
            w.login("carla")
            out = w.az.approve(
                t["id"], w.tokens["carla"],
                executors={ABORT_ACTIVE: lambda p:
                           w.o.abort(p["ceremony_id"], "carla", p["reason"])})
            self.assertEqual(out["status"], EXECUTED)
            self.assertEqual(w.o.state["ceremonies"][cid]["status"], "ABORTED")

    def test_purge_retired_four_eyes(self):
        w = AuthzWorld("/tmp/kc-authz-purge")
        with w.store.locked():
            w.generate()
            rot = w.rotate_done()
            old = w.o.dir.active_id("root-signing")
            w.o.publish_rotation(rot, "direct", old)
            retiring = [k for k in w.o.dir.versions_for_purpose("root-signing")
                        if k["status"] == "RETIRING"][0]["id"]
            # steward opens+prepares a DESTROY round; owner cannot approve
            # purge alone — the witness is the complementary approver.
            w.login("bruno")
            cid = w.destroy_opened(retiring)
            w.attest_confirm_destroy(cid)
            payload = {"ceremony_id": cid}
            t, _ = w.az.create_ticket(PURGE_RETIRED, payload,
                                      w.session("bruno"))
            w.login("alice")
            out = w.az.approve(
                t["id"], w.tokens["alice"],
                executors={PURGE_RETIRED: lambda p:
                           w.o.commit(p["ceremony_id"], "alice")})
            self.assertEqual(out["status"], EXECUTED)
            kv = w.o.dir.get(retiring)
            self.assertEqual(kv["status"], "DESTROYED")
            self.assertNotIn(retiring, w.o.state["wraps"])


class TestConcurrentApproval(unittest.TestCase):
    def test_concurrent_approvals_execute_at_most_once(self):
        w = AuthzWorld("/tmp/kc-authz-conc")
        with w.store.locked():
            w.generate()
            cid = w.rotate_done()
            old = w.o.dir.active_id("root-signing")
            w.login("diego")
            t, _ = w.az.create_ticket(
                PUBLISH_GENERATION,
                {"ceremony_id": cid, "expected_active": old},
                w.session("diego"))
            w.save()
        # two distinct owners-of-approval are not allowed (duty), so use one
        # approver token with concurrent threads: all but one must fail.
        with w.store.locked():
            w.login("alice")
            w.save()
        token = w.tokens["alice"]
        outcomes = []

        def approve():
            try:
                with w.store.locked():
                    wo = Orchestrator(w.store, clock=w.clock)
                    sm = SessionManager(wo.state, wo.audit, clock=w.clock)
                    azm = Authz(wo.state, wo.audit, sm, clock=w.clock)
                    azm.approve(
                        t["id"], token,
                        executors={PUBLISH_GENERATION: lambda p:
                                   wo.publish_rotation(p["ceremony_id"], "alice",
                                                       p["expected_active"])})
                    wo.save()
                outcomes.append("ok")
            except TicketClosed:
                outcomes.append("closed")
            except Exception as e:  # noqa: BLE001
                outcomes.append(type(e).__name__)

        threads = [threading.Thread(target=approve) for _ in range(6)]
        for x in threads:
            x.start()
        for x in threads:
            x.join()
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertEqual(len(outcomes), 6)
        with w.store.locked():
            w.reopen()
            actives = [k for k in w.o.dir.versions_for_purpose("root-signing")
                       if k["status"] == "ACTIVE"]
            self.assertEqual(len(actives), 1)
            self.assertEqual(w.az.get_public(t["id"])["status"], EXECUTED)


class TestExportFourEyes(unittest.TestCase):
    def test_bundle_records_party_token_digest_chain_and_result(self):
        w = AuthzWorld("/tmp/kc-authz-export")
        with w.store.locked():
            w.generate()
            cid = w.rotate_done()
            old = w.o.dir.active_id("root-signing")
            w.login("diego")
            t, _ = w.az.create_ticket(
                PUBLISH_GENERATION,
                {"ceremony_id": cid, "expected_active": old},
                w.session("diego"))
            w.login("alice")
            w.az.approve(
                t["id"], w.tokens["alice"],
                executors={PUBLISH_GENERATION: lambda p:
                           w.o.publish_rotation(p["ceremony_id"], "alice",
                                                p["expected_active"])})
            w.save()
            bundle = export_mod.build_bundle(w.o, w.sm, w.az)
        verdict = export_mod.verify_bundle(bundle)
        self.assertTrue(verdict["ok"], verdict["problems"])
        self.assertTrue(verdict["checks"]["four_eyes_tickets_ok"])
        bt = [x for x in bundle["auth_tickets"] if x["id"] == t["id"]][0]
        self.assertEqual(bt["creator"]["participant_id"], "diego")
        self.assertEqual(bt["approver"]["participant_id"], "alice")
        self.assertNotEqual(bt["creator"]["device_id"],
                            bt["approver"]["device_id"])
        self.assertTrue(bt["creator"]["token_id"]
                        and bt["approver"]["token_id"])
        self.assertEqual(len(bt["decision_chain"]), 3)

    def test_offline_verifier_detects_ticket_tampering(self):
        w = AuthzWorld("/tmp/kc-authz-tamper")
        with w.store.locked():
            w.generate()
            cid = w.rotate_done()
            old = w.o.dir.active_id("root-signing")
            w.login("diego")
            t, _ = w.az.create_ticket(
                PUBLISH_GENERATION,
                {"ceremony_id": cid, "expected_active": old},
                w.session("diego"))
            w.login("alice")
            w.az.approve(
                t["id"], w.tokens["alice"],
                executors={PUBLISH_GENERATION: lambda p:
                           w.o.publish_rotation(p["ceremony_id"], "alice",
                                                p["expected_active"])})
            w.save()
            bundle = export_mod.build_bundle(w.o, w.sm, w.az)

        # tamper 1: swap the approver identity in the exported ticket
        b2 = json.loads(json.dumps(bundle))
        bt = b2["auth_tickets"][0]
        bt["approver"]["participant_id"] = "diego"  # same person as creator
        v = export_mod.verify_bundle(b2)
        self.assertFalse(v["ok"])
        self.assertTrue(any("same person" in p for p in v["problems"]),
                        v["problems"])

        # tamper 2: delete the execution audit entry (chain breaks)
        b3 = json.loads(json.dumps(bundle))
        b3["audit"] = [e for e in b3["audit"]
                       if e["event"] != "authz_ticket_executed"]
        v3 = export_mod.verify_bundle(b3)
        self.assertFalse(v3["ok"])

        # tamper 3: flip the digest in the ticket
        b4 = json.loads(json.dumps(bundle))
        b4["auth_tickets"][0]["digest"] = "0" * 64
        v4 = export_mod.verify_bundle(b4)
        self.assertFalse(v4["ok"])
        self.assertFalse(v4["checks"]["four_eyes_tickets_ok"])


def _publish_preflight(w, frozen):
    def run(p):
        c = w.o.state["ceremonies"].get(p["ceremony_id"])
        if c is None:
            raise TargetStateChanged("missing")
        if c.get("published"):
            raise TargetStateChanged("already published")
        if w.o.dir.active_id(c["purpose"]) != p["expected_active"]:
            raise TargetStateChanged("current moved")
    return run


if __name__ == "__main__":
    unittest.main(verbosity=2)
