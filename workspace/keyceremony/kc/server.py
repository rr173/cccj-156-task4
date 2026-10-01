"""HTTP surface: ceremony console API + signing test interface.

Run:  python -m kc.server --root ./data --port 8080

Security model of the HTTP layer
--------------------------------
Every API call (apart from the login challenge/quote and the static console)
carries an operator session token. The token was minted only after a
registered terminal presented a fresh attestation quote, and binds
person + duty + terminal + attestation time validity (`kc.sessions`).

Read endpoints are released per duty (`kc.authz.READ_SCOPES`); device-step
endpoints additionally require the session to own the addressed terminal.

Four sensitive actions cannot be invoked directly on the HTTP surface -
modifying the rule set, terminating an active round, publishing a new key
generation and purging retired material. They run only when a frozen
four-eyes authorization ticket is approved by a different person, at a
different terminal, holding a complementary duty (`kc.authz`).

The underlying orchestrator (`kc.ceremony.Orchestrator`) is deliberately
not gated: scripts, tests and recovery consoles that import the library keep
full direct access.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import policy as P
from . import crypto
from . import authz as AZ
from .ceremony import Orchestrator
from .drills import DrillsManager
from .errors import (
    CeremonyError, CleanupBlocked, ConflictState, DrillFrozen, Forbidden,
    LeaseContention, NotFound, PolicyViolation, PreflightFailed,
    ProtectedOperation, RevisionConflict, TargetStateChanged,
)
from . import evidence as evidence_mod
from .fleet import Fleet
from .regions import RegionRegistry
from .sessions import SessionManager
from .storage import Store
from . import export as export_mod

CONSOLE_HTML = os.path.join(os.path.dirname(__file__), "console.html")

PUBLIC_GET = {"/", "/index.html", "/health"}
PUBLIC_POST = {"/api/session/login-challenge", "/api/session/login"}

# Device-step endpoints require the session to own the addressed terminal.
DEVICE_STEP_SUFFIXES = ("/attest", "/receive", "/confirm", "/submit-share")


class App:
    def __init__(self, root: str, clock=time.time,
                 session_ttl: int = 3600,
                 ticket_ttl: int = 600):
        self.store = Store(root)
        self.fleet = Fleet(os.path.join(root, "wallets"))
        self.clock = clock
        self.session_ttl = session_ttl
        self.ticket_ttl = ticket_ttl


class Handler(BaseHTTPRequestHandler):
    app: App = None

    def log_message(self, fmt, *args):
        pass  # quiet; audit log is the record

    # ---- plumbing --------------------------------------------------------
    def _send(self, code: int, obj):
        body = json.dumps(obj, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode())

    def _error(self, e: CeremonyError):
        body = {"error": e.code, "message": str(e)}
        blockers = getattr(e, "blockers", None)
        if blockers:
            body["blockers"] = blockers
        problems = getattr(e, "problems", None)
        if problems:
            body["problems"] = problems
        # RevisionConflict carries both revisions for the two editing UIs.
        for attr in ("base_revision", "current_revision",
                     "base_snapshot", "current_snapshot"):
            val = getattr(e, attr, None)
            if val is not None:
                body[attr] = val
        self._send(e.http_status, body)

    def _token(self) -> str:
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return h[len("Bearer "):].strip()
        return self.headers.get("X-Session-Token", "").strip()

    def _with_ctx(self, fn, *, require_auth: bool = True,
                  read_scope: str | None = None):
        """Parse body, open the store lock, build orch/sessions/authz,
        authenticate, then run fn(ctx). State is persisted after every call -
        including refused approvals, so ticket/session closures survive.
        """
        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except Exception:
            return self._send(400, {"error": "BAD_JSON"})
        try:
            with self.app.store.locked():
                orch = Orchestrator(self.app.store, clock=self.app.clock)
                sm = SessionManager(orch.state, orch.audit,
                                    clock=self.app.clock,
                                    ttl_seconds=self.app.session_ttl)
                az = AZ.Authz(orch.state, orch.audit, sm,
                              clock=self.app.clock,
                              ttl_seconds=self.app.ticket_ttl)
                dm = DrillsManager(orch.state, orch.audit, orch.seed,
                                   regions=RegionRegistry(orch.state),
                                   clock=self.app.clock)
                ctx = Ctx(orch, sm, az, body, self.app.fleet, dm)
                if require_auth:
                    ctx.session = sm.validate(self._token())
                    if read_scope is not None and not AZ.Authz.can_read(
                            ctx.session["role"], read_scope):
                        raise Forbidden(
                            f"duty {ctx.session['role']} may not read "
                            f"{read_scope}")
                try:
                    result = fn(ctx)
                except Exception:
                    orch.save()
                    raise
                orch.save()
            if result is None:
                # handler already responded (reserved for direct writes)
                return
            self._send(200, result)
        except CeremonyError as e:
            self._error(e)
        except KeyError as e:
            self._send(400, {"error": "MISSING_FIELD", "field": str(e)})
        except Exception as e:  # noqa: BLE001 - surface unexpected failures
            self._send(500, {"error": "INTERNAL", "message": str(e)})

    # ---- routing ---------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)
        if path in ("/", "/index.html"):
            return self._serve_console()
        if path == "/health":
            return self._send(200, {"ok": True})

        def run(ctx):
            az = ctx.authz
            az.expire_open()
            if path == "/api/session/me":
                return _session_view(ctx.session, ctx)
            if path == "/api/policies":
                return {"policies": list(ctx.orch.state["policies"].values())}
            if path == "/api/participants":
                return {"participants": ctx.orch.state["participants"],
                        "devices": ctx.orch.state["devices"]}
            if path == "/api/ceremonies":
                return {"ceremonies": ctx.orch.list_ceremonies()}
            if path == "/api/keys":
                purpose = q.get("purpose", [None])[0]
                keys = list(ctx.orch.state["keys"].values())
                if purpose:
                    keys = [k for k in keys if k["purpose"] == purpose]
                return {"keys": sorted(keys, key=lambda k: (k["purpose"],
                                                            k["version"])),
                        "purposes": ctx.orch.state["purposes"]}
            if path == "/api/tickets":
                statuses = tuple(q.get("status", ())) or None
                return {"tickets": az.list_tickets(statuses)}
            if path == "/api/drill-plans":
                return {"plans": ctx.drills.list_plans()}
            if path == "/api/drills":
                return {"drills": ctx.drills.list_drills()}
            if path.startswith("/api/drills/"):
                parts = path.strip("/").split("/")
                if len(parts) == 3:
                    return ctx.drills.get_drill(parts[2])
                if len(parts) == 4 and parts[3] == "evidence":
                    return ctx.drills.evidence(parts[2])
                if len(parts) == 4 and parts[3] == "failover-status":
                    return ctx.drills.failover_status(parts[2])
                if len(parts) == 4 and parts[3] == "mirror-stats":
                    return {"stats": ctx.drills.mirror_stats(parts[2])}
            if path.startswith("/api/drill-plans/"):
                parts = path.strip("/").split("/")
                if len(parts) == 3:
                    return ctx.drills.public_plan(parts[2])
            if path == "/api/drill-regions":
                reg = RegionRegistry(ctx.orch.state)
                return {"regions": [reg.get(n).config_summary()
                                    for n in reg.names()]}
            if path == "/api/audit":
                probs = ctx.orch.audit.verify(
                    crypto.ed25519.public_from_secret(ctx.orch.seed))
                return {"entries": ctx.orch.audit.entries,
                        "verify_problems": probs,
                        "verified": not probs}
            if path == "/api/export":
                return export_mod.build_bundle(ctx.orch, ctx.sessions,
                                               ctx.authz)
            if path.startswith("/api/ceremonies/"):
                cid = path.rsplit("/", 1)[-1]
                if cid not in ctx.orch.state["ceremonies"]:
                    raise NotFound(f"unknown ceremony {cid}")
                return ctx.orch.public_ceremony(cid)
            raise NotFound("unknown path")

        scope = _read_scope_for(path)
        self._with_ctx(run, read_scope=scope)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        if path in PUBLIC_POST:
            return self._with_ctx(lambda ctx: self._public_session_path(ctx),
                                  require_auth=False)

        def run(ctx):
            return self._dispatch(ctx, path)

        self._with_ctx(run)

    def _serve_console(self):
        try:
            with open(CONSOLE_HTML, "rb") as f:
                html = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        except FileNotFoundError:
            self._send(404, {"error": "console unavailable"})

    # ---- unauthenticated login endpoints ---------------------------------
    def _public_session_path(self, ctx):
        path = urlparse(self.path).path
        b = ctx.body
        if path == "/api/session/login-challenge":
            return ctx.sessions.login_challenge(b["device_id"])
        if path == "/api/session/login":
            quote = b.get("quote")
            # The browser terminal model supplies just the device id; the
            # pending single-use challenge is held server-side. A real remote
            # terminal may instead post its {challenge, quote} directly.
            ch_b64 = b.get("challenge")
            if ch_b64 is None:
                pending = ctx.orch.state["login_challenges"].get(b["device_id"])
                ch_b64 = pending["challenge"] if pending else None
            if quote is None:
                ch = ctx.orch.state["login_challenges"][b["device_id"]]
                ch_b64 = ch["challenge"]
                w = ctx.fleet.get(b["device_id"])
                if b.get("bad_measurement"):
                    import os as _os
                    live = _os.urandom(32)
                else:
                    live = None
                quote = w.quote(crypto.b64d(ch_b64),
                               live_measurement=live,
                               now=self.app.clock())
            return ctx.sessions.login(
                b["device_id"], ch_b64, quote,
                ttl_seconds=b.get("ttl_seconds"))
        raise NotFound("unknown path")

    # ---- authenticated dispatch ------------------------------------------
    def _dispatch(self, ctx, path: str):
        b = ctx.body
        o, az = ctx.orch, ctx.authz

        # ---- session management ----
        if path == "/api/session/logout":
            return ctx.sessions.logout(self._token())
        if path == "/api/session/relogin":
            # Re-attest on the same registered terminal and continue; open
            # tickets of this person/terminal remain actionable.
            ch = ctx.sessions.login_challenge(b["device_id"])
            w = ctx.fleet.get(b["device_id"])
            quote = w.quote(crypto.b64d(ch["challenge"]),
                            now=self.app.clock())
            return ctx.sessions.login(b["device_id"], ch["challenge"], quote,
                                      ttl_seconds=b.get("ttl_seconds"))

        # ---- four-eyes authorization tickets ----
        if path == "/api/tickets":
            AZ.Authz.require_cap(ctx.session, "ticket:create")
            op = b["operation"]
            payload = _normalize_ticket_payload(op, b.get("payload", {}))
            ticket, duplicate = az.create_ticket(op, payload, ctx.session)
            return {"ticket": ticket, "duplicate": duplicate}
        if path == "/api/tickets/approve":
            return self._approve_ticket(ctx)
        if path == "/api/tickets/withdraw":
            AZ.Authz.require_cap(ctx.session, "ticket:withdraw")
            return {"ticket": az.withdraw(b["ticket_id"], self._token())}

        # ---- enrollment / administration ----
        if path == "/api/participants":
            AZ.Authz.require_cap(ctx.session, "participant:enroll")
            rec = o.enroll_participant(
                b["participant_id"], b["name"], b["role"])
            if b.get("provision_device", True):
                did = b.get("device_id", "dev_" + b["participant_id"])
                if not ctx.fleet.has(did):
                    ctx.fleet.provision(did, b["name"])
                w = ctx.fleet.get(did)
                o.bind_device(b["participant_id"], w, label=b["role"])
                rec["device_id"] = did
            return rec
        if path == "/api/devices/revoke":
            AZ.Authz.require_cap(ctx.session, "device:revoke")
            did = b["device_id"]
            dev = o.state["devices"].get(did)
            if dev is None:
                raise NotFound(f"unknown terminal {did}")
            dev["revoked"] = True
            killed = ctx.sessions.revoke_terminal(did)
            closed = az.close_for_terminal(did)
            o.audit.append("device_revoked",
                           {"device_id": did,
                            "revoked_by": ctx.session["participant_id"],
                            "sessions_invalidated": killed,
                            "tickets_closed": closed})
            return {"device_id": did, "revoked": True,
                    "sessions_invalidated": killed,
                    "tickets_closed": closed}

        # ---- ceremony lifecycle ----
        if path == "/api/ceremonies/open":
            AZ.Authz.require_cap(ctx.session, "ceremony:open")
            return o.open_ceremony(
                b["kind"], b["policy_id"], b["purpose"],
                ctx.session["participant_id"],
                lost_participants=b.get("lost_participants"),
                replacement_specs=b.get("replacement_specs"),
                target_version=b.get("target_version"))
        if path.endswith("/abort"):
            raise ProtectedOperation(
                "aborting a round needs a four-eyes ABORT_ACTIVE ticket: "
                "POST /api/tickets then /api/tickets/approve")
        if path.endswith("/publish"):
            raise ProtectedOperation(
                "publishing a generation needs a four-eyes "
                "PUBLISH_GENERATION ticket")
        if path.endswith("/commit"):
            return self._commit(ctx, path)
        if any(path.endswith(suf) for suf in DEVICE_STEP_SUFFIXES):
            return self._device_step(ctx, path)

        # ---- signing test interface ----
        if path == "/api/sign":
            AZ.Authz.require_cap(ctx.session, "sign:use")
            return o.sign(b["purpose"], b["message"].encode())
        if path == "/api/verify":
            return o.verify(b["purpose"], b["message"].encode(), b["sig"])

        # ---- cross-region disaster recovery drills ----
        if path.startswith("/api/drill"):
            return self._drill_dispatch(ctx, path)
        raise NotFound("unknown path")

    # ---- device-step endpoints (session must own the terminal) -----------
    def _device_step(self, ctx, path: str):
        b = ctx.body
        cid, suffix = path.split("/")[3], path.rsplit("/", 1)[-1]
        did = b["device_id"]
        AZ.Authz.require_cap(ctx.session, "device:step")
        if ctx.session["device_id"] != did:
            raise Forbidden(
                f"token is bound to terminal {ctx.session['device_id']}; "
                f"it cannot drive {did}")
        fleet = ctx.fleet
        if suffix == "attest":
            return fleet.attest(ctx.orch, cid, did,
                                bad_measurement=b.get("bad_measurement", False))
        if suffix == "receive":
            return fleet.receive(ctx.orch, cid, did)
        if suffix == "confirm":
            return fleet.confirm(ctx.orch, cid, did, note=b.get("note", ""))
        if suffix == "submit-share":
            return fleet.submit_recovery(
                ctx.orch, cid, did,
                source_ceremony_id=b.get("source_ceremony_id"))
        raise NotFound("unknown path")

    # ---- commit: DESTROY (purge retired material) is four-eyes gated ------
    def _commit(self, ctx, path: str):
        b = ctx.body
        cid = path.split("/")[3]
        c = ctx.orch.state["ceremonies"].get(cid)
        if c is None:
            raise NotFound(f"unknown ceremony {cid}")
        if c["kind"] == P.DESTROY:
            raise ProtectedOperation(
                "committing DESTROY purges retired material and needs a "
                "four-eyes PURGE_RETIRED ticket "
                "(payload: {ceremony_id})")
        AZ.Authz.require_cap(ctx.session, "ceremony:open")
        return ctx.orch.commit(
            cid, ctx.session["participant_id"],
            expected_active=b.get("expected_active"))

    # ---- cross-region disaster recovery drills ---------------------------
    def _drill_dispatch(self, ctx, path: str):
        b = ctx.body
        dm = ctx.drills
        actor = ctx.session["participant_id"]
        cap = AZ.Authz.require_cap

        # ---- region administration (setup helper) ----
        if path == "/api/drill-regions/define":
            cap(ctx.session, "drill:plan")
            reg = RegionRegistry(ctx.orch.state)
            r = reg.define(
                b["name"], isolated=bool(b.get("isolated", False)),
                capacity=int(b.get("capacity", 1 << 30)),
                isolation=b.get("isolation", "AIRGAPPED"),
                egress=b.get("egress", "none"))
            reg.save(r)
            return r.config_summary()
        if path == "/api/drill-regions/put-object":
            cap(ctx.session, "drill:plan")
            import base64
            reg = RegionRegistry(ctx.orch.state)
            r = reg.get(b["region"])
            body = base64.b64decode(b.get("body_b64", "")) if b.get("body_b64") \
                else b.get("body", "").encode()
            meta = r.put_object(
                b["key"], body, b["category"],
                sealed=bool(b.get("sealed", False)),
                namespace=b.get("namespace", "prod"))
            reg.save(r)
            return meta
        if path == "/api/drill-regions/recovery-point":
            cap(ctx.session, "drill:plan")
            reg = RegionRegistry(ctx.orch.state)
            r = reg.get(b["region"])
            man = r.create_recovery_point(
                b["recovery_point"], b["object_keys"],
                dependency_versions=b.get("dependency_versions"),
                note=b.get("note", ""))
            reg.save(r)
            return {"recovery_point": man["id"],
                    "manifest_hash": man["manifest_hash"],
                    "n_objects": len(man["objects"])}

        # ---- plans (revisioned) ----
        if path == "/api/drill-plans":
            cap(ctx.session, "drill:plan")
            fields = self._plan_fields(b)
            if b.get("plan_id"):
                # the global error handler emits the 409 + both revisions
                return dm.update_plan(b["plan_id"], fields, actor,
                                      int(b["base_revision"]))
            return dm.create_plan(fields, actor)
        if path.endswith("/scan"):
            cap(ctx.session, "drill:scan")
            return dm.scan(path.split("/")[3], actor)
        if path.endswith("/start"):
            cap(ctx.session, "drill:run")
            return dm.start_drill(path.split("/")[3], actor)

        # ---- drill run / mirror / lease / cleanup ----
        if path.startswith("/api/drills/"):
            did = path.split("/")[3]
            suffix = path.rsplit("/", 1)[-1]
            if suffix == "stage":
                cap(ctx.session, "drill:run")
                return dm.run_stage(did)
            if suffix == "run-to-ready":
                cap(ctx.session, "drill:run")
                return dm.run_to_ready(did)
            if suffix == "window":
                cap(ctx.session, "drill:mirror")
                if b.get("close"):
                    return dm.close_window(did, actor)
                return dm.open_window(did, actor,
                                      seconds=b.get("seconds"))
            if suffix == "mirror":
                cap(ctx.session, "drill:mirror")
                return dm.mirror_request(did, b)
            if suffix == "resume":
                cap(ctx.session, "drill:mirror")
                return dm.resume_after_repair(
                    did, actor, note=b.get("note", ""))
            if suffix == "lease":
                cap(ctx.session, "drill:lease")
                return dm.acquire_lease(
                    did, b.get("instance_id", "web-console"), actor,
                    ttl_seconds=b.get("ttl_seconds"))
            if suffix == "failover-status":
                return dm.failover_status(did)
            if suffix == "failback":
                cap(ctx.session, "drill:failback")
                return dm.failback(did, actor, reason=b.get("reason", "manual"))
            if suffix == "archive-differences":
                cap(ctx.session, "drill:terminate")
                return dm.archive_differences(did)
            if suffix == "terminate":
                cap(ctx.session, "drill:terminate")
                return dm.terminate(did, actor)
            if suffix == "cleanup":
                cap(ctx.session, "drill:terminate")
                return dm.cleanup(did)
            raise NotFound("unknown drill action: " + suffix)
        raise NotFound("unknown drill path")

    @staticmethod
    def _plan_fields(b: dict) -> dict:
        return {
            "label": b["label"],
            "source_region": b["source_region"],
            "target_region": b["target_region"],
            "recovery_point": b["recovery_point"],
            "allowed_categories": b["allowed_categories"],
            "rto_seconds": int(b["rto_seconds"]),
            "rpo_seconds": int(b["rpo_seconds"]),
            "mirror_ratio": float(b.get("mirror_ratio", 0.1)),
            # passed through uncoerced: the manager validates that the
            # tolerance quota is a non-negative integer (floats/bools/strings
            # are rejected instead of silently truncating).
            "diff_threshold": b.get("diff_threshold", 0),
            "latency_threshold_ms": int(b.get("latency_threshold_ms", 500)),
        }

    # ---- ticket approval: frozen payload + preflight + one-shot execute ---
    def _approve_ticket(self, ctx):
        b = ctx.body
        ticket = ctx.authz.get_public(b["ticket_id"])
        op = ticket["operation"]
        payload = _normalize_ticket_payload(
            op, b.get("payload", ticket["payload"]))
        executors = {
            AZ.POLICY_CHANGE: self._exec_policy_change(ctx),
            AZ.ABORT_ACTIVE: self._exec_abort(ctx),
            AZ.PUBLISH_GENERATION: self._exec_publish(ctx),
            AZ.PURGE_RETIRED: self._exec_purge(ctx),
        }
        preflights = {
            AZ.POLICY_CHANGE: self._preflight_policy_change(ctx),
            AZ.ABORT_ACTIVE: self._preflight_abort(ctx),
            AZ.PUBLISH_GENERATION: self._preflight_publish(ctx),
            AZ.PURGE_RETIRED: self._preflight_purge(ctx),
        }
        out = ctx.authz.approve(
            b["ticket_id"], self._token(),
            executors=executors, preflights=preflights,
            presented_payload=payload)
        return {"ticket": out, "execution": out.get("execution")}

    # ======================================================================
    # payload normalization for protected operations
    # ======================================================================

    # -- executors -----------------------------------------------------------
    def _exec_policy_change(self, ctx):
        o = ctx.orch

        def run(p):
            if p.get("supersedes"):
                return o.revise_policy(
                    p["policy_id"], p.get("label", ""),
                    int(p["threshold"]),
                    [tuple(s) for s in p["slots"]],
                    purposes=tuple(p.get("purposes", ["root-signing"])),
                    handover_seconds=int(p.get("handover_seconds", 3600)),
                    ceremony_timeout_seconds=int(
                        p.get("ceremony_timeout_seconds", 1800)),
                    supersedes=p["supersedes"])
            return o.create_policy(
                p["policy_id"], p.get("label", ""), int(p["threshold"]),
                [tuple(s) for s in p["slots"]],
                purposes=tuple(p.get("purposes", ["root-signing"])),
                handover_seconds=int(p.get("handover_seconds", 3600)),
                ceremony_timeout_seconds=int(
                    p.get("ceremony_timeout_seconds", 1800)))
        return run

    def _exec_abort(self, ctx):
        o, session = ctx.orch, ctx.session

        def run(p):
            return o.abort(p["ceremony_id"], session["participant_id"],
                           p.get("reason", "four-eyes approved abort"))
        return run

    def _exec_publish(self, ctx):
        o = ctx.orch

        def run(p):
            return o.publish_rotation(
                p["ceremony_id"], ctx.session["participant_id"],
                p["expected_active"])
        return run

    def _exec_purge(self, ctx):
        o = ctx.orch

        def run(p):
            return o.commit(p["ceremony_id"], ctx.session["participant_id"],
                            expected_active=None)
        return run

    # -- preflights: re-validate target against the frozen payload ----------
    def _preflight_policy_change(self, ctx):
        o = ctx.orch

        def run(p):
            if p["policy_id"] in o.state["policies"] and not p.get("supersedes"):
                raise ConflictState(
                    f"policy {p['policy_id']} now exists; rule set changed")
            for pid, _role, did in p["slots"]:
                if pid not in o.state["participants"]:
                    raise NotFound(f"participant {pid} missing")
                dev = o.state["devices"].get(did)
                if not dev or dev["participant_id"] != pid \
                        or dev.get("revoked"):
                    raise PolicyViolation(
                        f"slot terminal {did} no longer valid for {pid}")
        return run

    def _preflight_abort(self, ctx):
        o = ctx.orch

        def run(p):
            c = o.state["ceremonies"].get(p["ceremony_id"])
            if c is None:
                raise NotFound("ceremony vanished")
            if c["status"] != "OPEN":
                raise TargetStateChanged(
                    f"ceremony already {c['status']}; nothing to terminate")
        return run

    def _preflight_publish(self, ctx):
        o = ctx.orch

        def run(p):
            c = o.state["ceremonies"].get(p["ceremony_id"])
            if c is None:
                raise NotFound("ceremony vanished")
            if c.get("published"):
                raise TargetStateChanged("generation already published")
            if c["kind"] != P.ROTATE or c["status"] != "COMPLETED":
                raise ConflictState("ceremony is not a completed ROTATE")
            cur = o.dir.active_id(c["purpose"])
            if cur != p["expected_active"]:
                raise TargetStateChanged(
                    f"current key moved: frozen {p['expected_active']}, "
                    f"now {cur}")
        return run

    def _preflight_purge(self, ctx):
        o = ctx.orch

        def run(p):
            c = o.state["ceremonies"].get(p["ceremony_id"])
            if c is None:
                raise NotFound("ceremony vanished")
            if c["status"] != "OPEN":
                raise TargetStateChanged(
                    f"ceremony already {c['status']}")
            if c["kind"] != P.DESTROY:
                raise PolicyViolation("ticket ceremony is not DESTROY")
        return run


class Ctx:
    def __init__(self, orch, sessions, authz, body, fleet, drills=None):
        self.orch = orch
        self.sessions = sessions
        self.authz = authz
        self.body = body
        self.fleet = fleet
        self.drills = drills
        self.session = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _read_scope_for(path: str) -> str | None:
    if path == "/api/session/me":
        return None
    if path in ("/api/policies", "/api/participants", "/api/ceremonies",
                "/api/keys", "/api/tickets"):
        return path.rsplit("/", 1)[-1]
    if path in ("/api/drill-plans", "/api/drills", "/api/drill-regions") \
            or path.startswith("/api/drills/"):
        return "drills"
    if path == "/api/audit":
        return "audit"
    if path == "/api/export":
        return "export"
    if path.startswith("/api/ceremonies/"):
        return "ceremonies"
    return None


_TICKET_PAYLOAD_KEYS = {
    AZ.POLICY_CHANGE: frozenset({
        "policy_id", "label", "threshold", "slots", "purposes",
        "handover_seconds", "ceremony_timeout_seconds", "supersedes"}),
    AZ.ABORT_ACTIVE: frozenset({"ceremony_id", "reason"}),
    AZ.PUBLISH_GENERATION: frozenset({"ceremony_id", "expected_active"}),
    AZ.PURGE_RETIRED: frozenset({"ceremony_id"}),
}


def _normalize_ticket_payload(operation: str, body: dict) -> dict:
    keys = _TICKET_PAYLOAD_KEYS.get(operation)
    if keys is None:
        raise PolicyViolation(f"unknown protected operation {operation}")
    return {k: body[k] for k in sorted(keys) if k in body}


def _session_view(session: dict, ctx: "Ctx") -> dict:
    role = session["role"]
    return {
        "token_id": session["token_id"],
        "participant_id": session["participant_id"],
        "name": ctx.orch.state["participants"][session["participant_id"]]["name"],
        "role": role,
        "device_id": session["device_id"],
        "measurement": session["measurement"],
        "quote_ts": session["quote_ts"],
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
        "read_scopes": sorted(AZ.READ_SCOPES.get(role, frozenset())),
        "capabilities": sorted(AZ.CAPABILITIES.get(role, frozenset())),
        "creator_duties": {op: sorted(roles)
                           for op, roles in AZ.CREATOR_DUTIES.items()
                           if role in roles},
        "approver_duties": {op: sorted(roles)
                            for op, roles in AZ.APPROVER_DUTIES.items()
                            if role in roles},
    }


def serve(root: str, port: int = 8080, host: str = "127.0.0.1",
          session_ttl: int = 3600, ticket_ttl: int = 600):
    app = App(root, session_ttl=session_ttl, ticket_ttl=ticket_ttl)
    Handler.app = app
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"key ceremony console: http://{host}:{port}/  (state in {root})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--session-ttl", type=int, default=3600,
                    help="operator session/attestation validity seconds")
    ap.add_argument("--ticket-ttl", type=int, default=600,
                    help="authorization ticket approval deadline seconds")
    a = ap.parse_args(argv)
    serve(a.root, a.port, a.host, a.session_ttl, a.ticket_ttl)


if __name__ == "__main__":
    main()
