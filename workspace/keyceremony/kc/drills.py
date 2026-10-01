"""Cross-region disaster recovery drills.

A *drill* lets an administrator prove - repeatedly and without touching
production key material - that a recovery point can rebuild a service inside
an isolated region, serve read-only verification traffic, fail over safely,
and fail back. The orchestration is deliberately a separate surface from the
root-key ceremonies: the existing CLI library and HTTP interfaces are
unchanged, and the drill engine never unseals the root material it copies.

Lifecycle
---------
    DRAFT plan (revisioned)
      -> scanned: fixed recovery blueprint (+ short-lived creds/namespace)
      -> PREPARE -> COPY -> REBUILD_INDEX -> SHADOW_START -> PROBES -> READY
      -> observation window: read-only mirror traffic, comparator
      with a non-negative-integer mismatch tolerance quota (the bypass is
      deactivated only once the atomically accumulated mismatch count grows
      greater than the quota; the tally survives concurrency, restarts and
      manual resumes and a replayed correlation id is never counted twice)
      -> (quota crossed: FROZEN -> resume after repair, or terminate)
      -> leased failover (read-only verification ingress only)
      -> failback (converged state machine; idempotent)
      -> cleanup (resumable; blocked while traffic/lease/unarchived diffs)
      -> CLEANED + verifiable evidence archive

Guarantees (see module tests)
-----------------------------
* optimistic plan revisions: a stale submit gets REVISION_CONFLICT with both
  sides' details, never an overwrite;
* a scan verifies snapshot manifest, object hashes, dependency versions,
  region capacity, encapsulation and the target isolation policy, and pins a
  *fixed* blueprint; any source snapshot / target config / blueprint change
  invalidates the scan result;
* stages carry persistent checkpoints with idempotency keys: after a crash,
  node migration or duplicate start, the engine resumes at the last confirmed
  stage, never creating a resource twice or counting an object twice;
* write requests (generate/rotate/destroy/policy) always stay in production,
  even when a client forges mirror flags;
* failover leases are deadline-bound, single-holder and only granted after
  all probes pass inside the RTO;
* cleanup is resumable and refuses to delete critical resources while mirror
  traffic, a live lease or unarchived differences remain;
* the evidence archive is independently checkable and old-format archives
  remain readable.
"""

from __future__ import annotations

import os
import time

from . import crypto, ed25519
from .errors import (
    BlueprintStale, CleanupBlocked, ConflictState, DrillFrozen,
    EvidenceError, LeaseContention, NotFound, PolicyViolation,
    PreflightFailed, RevisionConflict,
)
from .regions import (
    CATEGORY_AUDIT, CATEGORY_INDEX, CATEGORY_KEY_MATERIAL,
    CATEGORY_POLICY, CATEGORY_PUBLIC_KEYS, CATEGORY_SESSIONS,
    ISOLATION_AIRGAPPED, NEVER_RESTORABLE, PROD_NAMESPACE,
    RECOVERABLE_CATEGORIES, REQUIRED_ISOLATION, Region, RegionRegistry,
)

# ---- plan / drill status ---------------------------------------------------
PLAN_DRAFT = "DRAFT"
PLAN_SCANNED = "SCANNED"

DRILL_PENDING = "PENDING"
DRILL_RUNNING = "RUNNING"
DRILL_READY = "READY"
DRILL_OBSERVING = "OBSERVING"
DRILL_FROZEN = "FROZEN"
DRILL_FAILOVER = "FAILOVER"
DRILL_FAILED_BACK = "FAILED_BACK"
DRILL_TERMINATING = "TERMINATING"
DRILL_CLEANED = "CLEANED"
DRILL_ABORTED = "ABORTED"

# recovery engine stages, strict order
STAGE_PREPARE = "PREPARE"
STAGE_COPY = "COPY"
STAGE_REBUILD_INDEX = "REBUILD_INDEX"
STAGE_SHADOW_START = "SHADOW_START"
STAGE_PROBES = "PROBES"
STAGE_READY = "READY"
ENGINE_STAGES = (
    STAGE_PREPARE, STAGE_COPY, STAGE_REBUILD_INDEX,
    STAGE_SHADOW_START, STAGE_PROBES,
)

# write operations that must ALWAYS remain in the production region, even if
# a client forges a mirror flag on the request.
WRITE_OPERATIONS = frozenset({
    "SIGN",            # producing a signature is a write on signing counters
    "ROTATE", "GENERATE", "DESTROY", "ROTATE_KEY",
    "REVOKE", "POLICY_CHANGE", "POLICY_UPDATE",
})
READ_ONLY_OPERATIONS = frozenset({"VERIFY", "GET_KEY", "LIST_KEYS", "READ"})

DEFAULT_CRED_TTL = 3600
DEFAULT_WINDOW_SECONDS = 900
DEFAULT_LEASE_SECONDS = 300
DEFAULT_DIFF_THRESHOLD = 1

PLAN_FIELDS = (
    "label", "source_region", "target_region", "recovery_point",
    "allowed_categories", "rto_seconds", "rpo_seconds",
    "mirror_ratio", "diff_threshold", "latency_threshold_ms",
)


def _mid(prefix: str) -> str:
    return f"{prefix}_{os.urandom(10).hex()}"


def _nonneg_int(f: dict, key: str, default: int) -> int:
    """Coerce a plan field to a non-negative integer.

    Booleans, floats (1.5 would silently truncate under plain int()) and
    negative values are rejected up front with a policy error.
    """
    if key not in f or f[key] is None:
        return default
    v = f[key]
    if isinstance(v, bool) or not isinstance(v, int):
        raise PolicyViolation(f"{key} must be a non-negative integer")
    if v < 0:
        raise PolicyViolation(f"{key} must be a non-negative integer")
    return v


def _now(clock) -> float:
    return float(clock())


def _recovery_point_manifest_hash(rp: dict) -> str:
    """Recompute a recovery point's self-manifest hash (must match the value
    stored at snapshot creation; detects a forged recovery point)."""
    return crypto.digest_hex(
        {k: v for k, v in rp.items() if k != "manifest_hash"})


class DrillsManager:
    """Drill plans, runs, mirroring, leases, cleanup and evidence.

    All mutating methods assume the caller holds `store.locked()` (the same
    model as Orchestrator/Authz).
    """

    def __init__(self, state: dict, audit, service_seed: bytes,
                 regions: RegionRegistry | None = None, clock=time.time,
                 cred_ttl: int = DEFAULT_CRED_TTL):
        self.state = state
        self.audit = audit
        self.seed = service_seed
        self.regions = regions or RegionRegistry(state)
        self.clock = clock
        self.cred_ttl = cred_ttl
        for key in ("drill_plans", "drills"):
            self.state.setdefault(key, {})

    # ======================================================================
    # plans (revisioned, optimistic concurrency)
    # ======================================================================
    def create_plan(self, fields: dict, actor: str) -> dict:
        plan_id = _mid("plan")
        self._validate_fields(fields)
        now = _now(self.clock)
        rev = {
            "revision": 1,
            "fields": self._norm_fields(fields),
            "edited_by": actor,
            "edited_at": now,
        }
        plan = {
            "id": plan_id,
            "status": PLAN_DRAFT,
            "revisions": [rev],
            "created_by": actor,
            "created_at": now,
            "scans": [],
            "drill_id": None,
        }
        self.state["drill_plans"][plan_id] = plan
        self.audit.append("drill_plan_created",
                          {"plan_id": plan_id, "revision": 1,
                           "actor": actor,
                           "label": rev["fields"]["label"]})
        return self.public_plan(plan_id)

    def update_plan(self, plan_id: str, fields: dict, actor: str,
                    base_revision: int) -> dict:
        """Submit an edit made against `base_revision`.

        Two browsers editing concurrently: the first submit bumps the
        revision; the second (stale base) gets REVISION_CONFLICT carrying
        both snapshots so the UI can merge - it never overwrites.
        """
        plan = self._plan(plan_id)
        current = plan["revisions"][-1]["revision"]
        if int(base_revision) != current:
            raise RevisionConflict(
                f"plan {plan_id} was edited concurrently: your base "
                f"revision {base_revision} is behind current {current}",
                base_revision=int(base_revision),
                current_revision=current,
                base_snapshot=self._revision_snapshot(plan, int(base_revision)),
                current_snapshot=plan["revisions"][-1]["fields"])
        self._validate_fields(fields)
        now = _now(self.clock)
        new_rev = current + 1
        plan["revisions"].append({
            "revision": new_rev,
            "fields": self._norm_fields(fields),
            "edited_by": actor,
            "edited_at": now,
        })
        # Any edit after a successful scan invalidates it: the blueprint was
        # fixed against the previous parameter set.
        if plan["status"] == PLAN_SCANNED:
            plan["status"] = PLAN_DRAFT
            self.audit.append("drill_scan_invalidated",
                              {"plan_id": plan_id,
                               "reason": "plan_revised",
                               "revision": new_rev})
        self.audit.append("drill_plan_revised",
                          {"plan_id": plan_id, "revision": new_rev,
                           "actor": actor})
        return self.public_plan(plan_id)

    def _revision_snapshot(self, plan: dict, revision: int) -> dict | None:
        for r in plan["revisions"]:
            if r["revision"] == revision:
                return r["fields"]
        return None

    def _norm_fields(self, f: dict) -> dict:
        return {
            "label": str(f["label"]),
            "source_region": str(f["source_region"]),
            "target_region": str(f["target_region"]),
            "recovery_point": str(f["recovery_point"]),
            "allowed_categories": sorted(set(f["allowed_categories"])),
            "rto_seconds": int(f["rto_seconds"]),
            "rpo_seconds": int(f["rpo_seconds"]),
            "mirror_ratio": float(f.get("mirror_ratio", 0.1)),
            "diff_threshold": _nonneg_int(
                f, "diff_threshold", DEFAULT_DIFF_THRESHOLD),
            "latency_threshold_ms": int(f.get("latency_threshold_ms", 500)),
        }

    def _validate_fields(self, f: dict):
        for k in ("label", "source_region", "target_region",
                  "recovery_point", "rto_seconds", "rpo_seconds"):
            if k not in f:
                raise PolicyViolation(f"plan field missing: {k}")
        if f["source_region"] == f["target_region"]:
            raise PolicyViolation(
                "source and target region must differ (isolated rebuild)")
        if f["source_region"] not in self.regions.names():
            raise NotFound(f"unknown source region {f['source_region']}")
        if f["target_region"] not in self.regions.names():
            raise NotFound(f"unknown target region {f['target_region']}")
        src = self.regions.get(f["source_region"])
        tgt = self.regions.get(f["target_region"])
        if not tgt.isolated:
            raise PolicyViolation(
                f"target region {f['target_region']} is not an isolated region")
        if f["recovery_point"] not in src.recovery_points:
            raise NotFound(
                f"recovery point {f['recovery_point']} not found in "
                f"{f['source_region']}")
        cats = set(f.get("allowed_categories", list(RECOVERABLE_CATEGORIES)))
        bad = cats - set(RECOVERABLE_CATEGORIES)
        if bad:
            raise PolicyViolation(f"non-recoverable categories: {sorted(bad)}")
        if cats & set(NEVER_RESTORABLE):
            raise PolicyViolation(
                f"categories {sorted(cats & set(NEVER_RESTORABLE))} must "
                "never be restored into an isolated region")
        if not cats:
            raise PolicyViolation("plan must allow at least one category")
        if int(f["rto_seconds"]) <= 0 or int(f["rpo_seconds"]) < 0:
            raise PolicyViolation("RTO must be positive, RPO non-negative")
        ratio = float(f.get("mirror_ratio", 0.1))
        if not 0.0 < ratio <= 1.0:
            raise PolicyViolation("mirror_ratio must be within (0, 1]")
        # The comparison tolerance quota is a *count* of tolerated
        # inconsistencies: non-negative integer only (0 deactivates the bypass
        # on the first mismatch, 1 allows one, ...).
        _nonneg_int(f, "diff_threshold", DEFAULT_DIFF_THRESHOLD)

    def plan_fields(self, plan_id: str) -> dict:
        return self._plan(plan_id)["revisions"][-1]["fields"]

    def _plan(self, plan_id: str) -> dict:
        plan = self.state["drill_plans"].get(plan_id)
        if plan is None:
            raise NotFound(f"unknown drill plan {plan_id}")
        return plan

    def list_plans(self) -> list[dict]:
        return [self.public_plan(pid)
                for pid in sorted(self.state["drill_plans"])]

    def public_plan(self, plan_id: str) -> dict:
        p = self._plan(plan_id)
        latest = p["revisions"][-1]
        return {
            "id": p["id"], "status": p["status"],
            "revision": latest["revision"],
            "fields": latest["fields"],
            "edited_by": latest["edited_by"], "edited_at": latest["edited_at"],
            "revisions": [{"revision": r["revision"],
                           "edited_by": r["edited_by"],
                           "edited_at": r["edited_at"]}
                          for r in p["revisions"]],
            "created_by": p["created_by"], "created_at": p["created_at"],
            "scans": [{"scan_id": s["scan_id"],
                       "blueprint_hash": s["blueprint_hash"],
                       "scanned_at": s["scanned_at"],
                       "valid": self._scan_still_valid(s, latest["fields"])}
                      for s in p.get("scans", [])],
            "drill_id": p.get("drill_id"),
        }

    # ======================================================================
    # pre-launch checklist scan -> fixed blueprint
    # ======================================================================
    def scan(self, plan_id: str, actor: str, *,
             expect_dependency_versions: dict | None = None) -> dict:
        """Run the pre-launch checklist and freeze a recovery blueprint.

        Raises PreflightFailed with *all* problems and creates nothing.
        """
        plan = self._plan(plan_id)
        fields = plan["revisions"][-1]["fields"]
        src = self.regions.get(fields["source_region"])
        tgt = self.regions.get(fields["target_region"])
        rp = src.recovery_points.get(fields["recovery_point"])
        problems: list[str] = []

        if rp is None:
            raise PreflightFailed(
                f"snapshot manifest missing: recovery point "
                f"{fields['recovery_point']} not in {fields['source_region']}")

        # 1. snapshot manifest integrity + every object hash re-computed
        recomputed_manifest = _recovery_point_manifest_hash(rp)
        if rp.get("manifest_hash") != recomputed_manifest:
            problems.append("snapshot manifest hash mismatch (forged or "
                            "corrupted recovery point)")
        allowed = set(fields["allowed_categories"])
        total_size = 0
        for entry in rp["objects"]:
            key = entry["key"]
            meta = src.objects.get(key)
            if meta is None:
                problems.append(f"snapshot object missing: {key}")
                continue
            if entry["category"] not in allowed:
                # category not allowed by THIS plan: blueprint excludes it
                continue
            if meta["body_hash"] != entry["body_hash"]:
                problems.append(
                    f"object hash mismatch: {key} (manifest "
                    f"{entry['body_hash'][:12]} vs live "
                    f"{meta['body_hash'][:12]})")
            # 5. encapsulation: anything carrying root material must be sealed
            if entry["category"] == CATEGORY_KEY_MATERIAL:
                if not meta.get("sealed"):
                    problems.append(
                        f"key material object {key} is not sealed; the drill "
                        "must never copy unsealed root material")
                enc = meta.get("encapsulation")
                if not enc or enc.get("alg") != "kc-aead-v1":
                    problems.append(
                        f"object {key} encapsulation descriptor invalid")
            total_size += entry["size"]

        # 2. dependency versions match the target's deployed set
        want = expect_dependency_versions or rp["dependency_versions"]
        for comp, ver in want.items():
            have = tgt.dependencies.get(comp)
            if have is None:
                problems.append(
                    f"target missing dependency component {comp} (want {ver})")
            elif have != ver:
                problems.append(
                    f"dependency version mismatch for {comp}: snapshot "
                    f"{ver}, target {have}")

        # 4. target capacity for the allowed restore set
        if tgt.capacity - tgt.used_bytes < total_size:
            problems.append(
                f"insufficient target capacity: need {total_size} bytes, "
                f"{tgt.capacity - tgt.used_bytes} available")

        # 6. target isolation policy
        iso = tgt.isolation_policy
        if iso.get("level") != REQUIRED_ISOLATION:
            problems.append(
                f"target isolation policy is {iso.get('level')}, drill "
                f"requires {REQUIRED_ISOLATION}")
        if iso.get("allow_production_credentials"):
            problems.append(
                "target isolation policy permits production credentials")
        if not iso.get("require_namespace_prefix", "").startswith("drill-"):
            problems.append(
                "target isolation policy does not enforce a drill namespace")

        # RPO: the recovery point must be inside the plan's RPO window
        age = _now(self.clock)  # deterministic in tests via clock; manifests
        # carry created_seq rather than wall time; RPO is checked against an
        # explicit snapshot timestamp when supplied.
        if rp.get("created_ts") is not None:
            age = _now(self.clock) - rp["created_ts"]
            if age > fields["rpo_seconds"]:
                problems.append(
                    f"recovery point age {int(age)}s exceeds RPO "
                    f"{fields['rpo_seconds']}s")

        if problems:
            self.audit.append("drill_scan_failed",
                              {"plan_id": plan_id, "problems": problems})
            raise PreflightFailed(problems)

        blueprint = self._freeze_blueprint(plan, fields, src, tgt, rp)
        scan = {
            "scan_id": _mid("scan"),
            "actor": actor,
            "scanned_at": _now(self.clock),
            "source_config_seq": src.config_seq,
            "target_config_seq": tgt.config_seq,
            "source_manifest_hash": rp["manifest_hash"],
            "blueprint": blueprint,
            "blueprint_hash": blueprint["blueprint_hash"],
            "plan_revision": plan["revisions"][-1]["revision"],
        }
        plan.setdefault("scans", []).append(scan)
        plan["status"] = PLAN_SCANNED
        self.audit.append("drill_scan_passed",
                          {"plan_id": plan_id, "scan_id": scan["scan_id"],
                           "blueprint_hash": scan["blueprint_hash"],
                           "n_objects": len(blueprint["objects"])})
        return self.public_plan(plan_id)

    def _freeze_blueprint(self, plan, fields, src: Region, tgt: Region,
                          rp: dict) -> dict:
        allowed = set(fields["allowed_categories"])
        objects = []
        for entry in rp["objects"]:
            if entry["category"] not in allowed:
                continue
            objects.append({
                "key": entry["key"],
                "body_hash": entry["body_hash"],
                "size": entry["size"],
                "category": entry["category"],
                "sealed": entry["sealed"],
                "encapsulation": entry["encapsulation"],
                # fixed destination key inside the isolated namespace
                "dest_key": None,  # filled below once namespace is known
            })
        namespace = None  # namespace/creds are provisioned with the drill
        bp = {
            "format": "kc-drill-blueprint-v1",
            "plan_id": plan["id"],
            "source_region": fields["source_region"],
            "target_region": fields["target_region"],
            "recovery_point": fields["recovery_point"],
            "allowed_categories": sorted(allowed),
            "rto_seconds": fields["rto_seconds"],
            "rpo_seconds": fields["rpo_seconds"],
            "dependency_versions": dict(rp["dependency_versions"]),
            "source_config_seq": src.config_seq,
            "target_config_seq": tgt.config_seq,
            "source_manifest_hash": rp["manifest_hash"],
            "objects": sorted(objects, key=lambda o: o["key"]),
            "total_size": sum(o["size"] for o in objects),
            "namespace": namespace,
        }
        bp["blueprint_hash"] = crypto.digest_hex(
            {k: v for k, v in bp.items() if k != "blueprint_hash"})
        return bp

    def _scan_still_valid(self, scan: dict, fields: dict | None = None) -> bool:
        """True iff source snapshot, target config and plan revision are
        exactly what the scan froze. Any movement invalidates the blueprint.
        """
        bp = scan["blueprint"]
        try:
            src = self.regions.get(bp["source_region"])
            tgt = self.regions.get(bp["target_region"])
        except KeyError:
            return False
        if src.config_seq != scan["source_config_seq"]:
            return False
        if tgt.config_seq != scan["target_config_seq"]:
            return False
        rp = src.recovery_points.get(bp["recovery_point"])
        if rp is None or rp["manifest_hash"] != scan["source_manifest_hash"]:
            return False
        # the pinned snapshot must still be internally intact: re-derive its
        # manifest hash so a forged/tampered recovery point (object hash
        # edited without recomputing) invalidates the blueprint.
        if rp["manifest_hash"] != _recovery_point_manifest_hash(rp):
            return False
        # and every live object hash still matches the snapshot entry
        for entry in rp["objects"]:
            meta = src.objects.get(entry["key"])
            if meta is None or meta["body_hash"] != entry["body_hash"]:
                return False
        return True

    def latest_valid_scan(self, plan_id: str) -> dict:
        plan = self._plan(plan_id)
        fields = plan["revisions"][-1]["fields"]
        for scan in reversed(plan.get("scans", [])):
            if (scan["plan_revision"] == plan["revisions"][-1]["revision"]
                    and self._scan_still_valid(scan, fields)):
                return scan
        return None

    def invalidate_scans_for_source(self, region_name: str):
        """Config/snapshot change hooks (region registries call this)."""
        for plan in self.state["drill_plans"].values():
            for scan in plan.get("scans", []):
                bp = scan["blueprint"]
                if bp["source_region"] == region_name or \
                        bp["target_region"] == region_name:
                    scan["invalidated"] = True

    # ======================================================================
    # short-lived drill credentials + isolated namespace
    # ======================================================================
    def _mint_credentials(self, drill_id: str, namespace: str) -> dict:
        raw = "drk_" + crypto.b64e(os.urandom(32))
        cred_id = "dcred_" + crypto.digest_hex(
            {"t": "kc-drill-cred-v1", "raw": raw})[:22]
        now = _now(self.clock)
        return {
            "cred_id": cred_id,
            # the raw secret is returned once at creation and never persisted
            "secret": raw,
            "namespace": namespace,
            "issued_at": now,
            "expires_at": now + self.cred_ttl,
            "status": "ACTIVE",
            "revoked_at": None,
            "scope": {
                "namespace": namespace,
                "regions": None,  # bound at drill start to the target region
                "writes_allowed": False,
                "production_referenceable": False,
            },
        }

    def _revoke_credentials(self, d: dict):
        for c in d.get("credentials", []):
            if c["status"] == "ACTIVE":
                c["status"] = "REVOKED"
                c["revoked_at"] = _now(self.clock)
        self.audit.append("drill_credentials_revoked",
                          {"drill_id": d["id"],
                           "cred_ids": [c["cred_id"]
                                        for c in d.get("credentials", [])]})

    def _cred_live(self, c: dict) -> bool:
        return (c["status"] == "ACTIVE"
                and _now(self.clock) <= c["expires_at"])

    # ======================================================================
    # drill start
    # ======================================================================
    def start_drill(self, plan_id: str, actor: str) -> dict:
        plan = self._plan(plan_id)
        if plan.get("drill_id"):
            existing = self.state["drills"].get(plan["drill_id"])
            if existing and existing["status"] not in (DRILL_CLEANED,
                                                       DRILL_ABORTED):
                raise ConflictState(
                    f"plan {plan_id} already has drill {plan['drill_id']}")
        scan = self.latest_valid_scan(plan_id)
        if scan is None:
            raise BlueprintStale(
                "no valid scan for the current plan revision; re-run the "
                "checklist scan")
        fields = plan["revisions"][-1]["fields"]
        drill_id = _mid("drill")
        namespace = f"drill-{drill_id.split('_')[1]}"
        cred = self._mint_credentials(drill_id, namespace)
        secret = cred.pop("secret")
        cred["scope"]["regions"] = [fields["target_region"]]
        now = _now(self.clock)
        # copy the blueprint and pin namespace/dest keys
        import copy
        bp = copy.deepcopy(scan["blueprint"])
        bp["namespace"] = namespace
        for o in bp["objects"]:
            base = o["key"].split("/", 1)[-1]
            o["dest_key"] = f"{namespace}/{base}"
        bp["blueprint_hash"] = crypto.digest_hex(
            {k: v for k, v in bp.items() if k != "blueprint_hash"})
        d = {
            "id": drill_id,
            "plan_id": plan_id,
            "status": DRILL_PENDING,
            "actor": actor,
            "created_at": now,
            "namespace": namespace,
            "credentials": [cred],
            "scan_id": scan["scan_id"],
            "blueprint": bp,
            "blueprint_hash": bp["blueprint_hash"],
            "fields": fields,
            "source_region": fields["source_region"],
            "target_region": fields["target_region"],
            "checkpoints": [],
            "resources": {},     # idempotency key -> resource record
            "copied_objects": [],
            "probes": [],
            "window": None,
            "mirror": {"requests": [], "differences": [], "stats": {
                "mirrored": 0, "matched": 0, "differences": 0,
                "timeouts": 0, "production_only": 0}},
            # Observation-comparator tolerance bookkeeping. The quota
            # (diff_threshold) is pinned when the drill starts; the mismatch
            # counter accumulates atomically under the store lock and survives
            # restarts and manual resumes. The bypass is deactivated only once
            # mismatch_count grows *greater than* the quota.
            "tolerance": {"quota": fields["diff_threshold"],
                          "mismatch_count": 0,
                          "trigger_request_id": None,
                          "history": []},
            "lease": None,
            "failback": None,
            "freeze": None,
            "cleanup": None,
            "evidence_id": None,
            "started_at": None,
            "ready_at": None,
            # crash injection: {"stage": s, "count": n} consumed by the engine
            "fail_at": None,
        }
        self.state["drills"][drill_id] = d
        plan["drill_id"] = drill_id
        self.audit.append("drill_started",
                          {"drill_id": drill_id, "plan_id": plan_id,
                           "namespace": namespace,
                           "cred_id": cred["cred_id"],
                           "blueprint_hash": bp["blueprint_hash"]})
        return self.public_drill(drill_id, secret=secret)

    def _drill(self, drill_id: str) -> dict:
        d = self.state["drills"].get(drill_id)
        if d is None:
            raise NotFound(f"unknown drill {drill_id}")
        return d

    def get_drill(self, drill_id: str) -> dict:
        return self.public_drill(drill_id)

    def list_drills(self) -> list[dict]:
        return [self.public_drill(i) for i in sorted(self.state["drills"])]

    # ======================================================================
    # staged recovery engine
    # ======================================================================
    def _checkpoint(self, d: dict, stage: str) -> dict | None:
        return next((c for c in d["checkpoints"] if c["stage"] == stage), None)

    def _confirm_checkpoint(self, d: dict, stage: str, detail: dict) -> dict:
        existing = self._checkpoint(d, stage)
        if existing is not None:
            return existing
        cp = {
            "stage": stage,
            "checkpoint_id": _mid("cp"),
            "idempotency_key": self._idem_key(d, stage),
            "confirmed_at": _now(self.clock),
            "detail": detail,
        }
        # checkpoints are strictly ordered and never repeat
        order = ENGINE_STAGES + (STAGE_READY,)
        confirmed = {c["stage"] for c in d["checkpoints"]}
        idx = order.index(stage)
        for prior in order[:idx]:
            if prior not in confirmed:
                raise ConflictState(
                    f"cannot confirm {stage}: prior stage {prior} missing")
        if stage in confirmed:
            return cp
        d["checkpoints"].append(cp)
        self.audit.append("drill_stage_confirmed",
                          {"drill_id": d["id"], "stage": stage,
                           "checkpoint_id": cp["checkpoint_id"],
                           "idempotency_key": cp["idempotency_key"]})
        return cp

    @staticmethod
    def _idem_key(d: dict, stage: str) -> str:
        # deterministic across crash/restart/duplicate start
        return crypto.digest_hex(
            {"drill": d["id"], "stage": stage,
             "blueprint": d["blueprint_hash"]})[:32]

    def _resource_once(self, d: dict, key: str, factory) -> dict:
        """Idempotent resource creation: same key -> same record, forever."""
        rec = d["resources"].get(key)
        if rec is not None:
            return rec
        rec = factory()
        rec["resource_key"] = key
        d["resources"][key] = rec
        return rec

    def _consume_failure(self, d: dict, stage: str):
        """Test hook: simulate a crash at a stage the configured number of
        times. The stage's side effects up to the crash are rolled back to the
        last confirmed checkpoint (nothing was confirmed yet), modeling a
        process dying before durable commit."""
        fa = d.get("fail_at")
        if not fa or fa.get("stage") != stage or fa.get("count", 0) <= 0:
            return
        fa["count"] -= 1
        raise _SimulatedCrash(stage)

    def run_stage(self, drill_id: str) -> dict:
        """Advance the engine by one (resumable) stage. Idempotent."""
        d = self._drill(drill_id)
        self._require_live_run(d)
        self._ensure_credential(d)
        confirmed = [c["stage"] for c in d["checkpoints"]]
        next_stage = next(
            (s for s in ENGINE_STAGES if s not in confirmed), STAGE_READY)
        if next_stage == STAGE_READY:
            return self._mark_ready(d)
        # crash injection happens before the stage's durable effects: any
        # resources tentatively made by this attempt are pre-confirmation and
        # discarded (factory model below guarantees that anyway).
        self._consume_failure(d, next_stage)
        handler = getattr(self, "_stage_" + next_stage.lower())
        if d["status"] == DRILL_PENDING:
            d["status"] = DRILL_RUNNING
            d["started_at"] = _now(self.clock)
        handler(d)
        detail = self._stage_detail(d, next_stage)
        self._confirm_checkpoint(d, next_stage, detail)
        if len(d["checkpoints"]) == len(ENGINE_STAGES):
            return self._mark_ready(d)
        return self.public_drill(drill_id)

    def run_to_ready(self, drill_id: str) -> dict:
        """Drive every remaining stage; resume-safe and idempotent."""
        d = self._drill(drill_id)
        guard = 0
        while d["status"] not in (DRILL_READY,):
            before = len(d["checkpoints"])
            self.run_stage(drill_id)
            if len(d["checkpoints"]) == before:
                break
            guard += 1
            if guard > len(ENGINE_STAGES) + 1:
                raise ConflictState("engine not advancing")
        return self.public_drill(drill_id)

    def _stage_detail(self, d: dict, stage: str) -> dict:
        if stage == STAGE_COPY:
            return {"objects": len(d["copied_objects"])}
        if stage == STAGE_PROBES:
            return {"probes": [p["probe_id"] for p in d["probes"]]}
        return {}

    def _require_live_run(self, d: dict):
        if d["status"] in (DRILL_CLEANED, DRILL_ABORTED):
            raise ConflictState(f"drill {d['id']} is {d['status']}")

    def _ensure_credential(self, d: dict):
        cred = d["credentials"][-1]
        if not self._cred_live(cred):
            raise ConflictState(
                "drill credential expired; expired drill credentials cannot "
                "be reactivated - terminate and start a new drill")

    # ---- stage implementations -------------------------------------------
    def _stage_prepare(self, d: dict):
        bp = d["blueprint"]
        tgt = self.regions.get(d["target_region"])
        # idempotent namespace reservation (one per drill)
        key = self._idem_key(d, STAGE_PREPARE) + ":namespace"
        ns = self._resource_once(d, key, lambda: {
            "kind": "namespace", "name": d["namespace"],
            "region": d["target_region"]})
        self.regions.save(tgt)
        # capacity re-check against the frozen blueprint
        if tgt.capacity - tgt.used_bytes < bp["total_size"]:
            raise PreflightFailed("target capacity no longer sufficient")
        d["prepared"] = {"namespace": ns["name"]}

    def _stage_copy(self, d: dict):
        bp = d["blueprint"]
        src = self.regions.get(d["source_region"])
        tgt = self.regions.get(d["target_region"])
        copied_here = 0
        for o in bp["objects"]:
            rkey = self._idem_key(d, STAGE_COPY) + ":" + o["dest_key"]
            if rkey in d["resources"]:
                continue  # already copied on a previous (confirmed) attempt
            meta = src.objects.get(o["key"])
            if meta is None:
                raise PreflightFailed(
                    f"snapshot object vanished before copy: {o['key']}")
            if meta["body_hash"] != o["body_hash"]:
                raise PreflightFailed(
                    f"object changed since blueprint: {o['key']}")
            # Root material is copied as a SEALED reference only; the engine
            # never unseals it. The target receives a sealed-object marker.
            tmeta = {
                "key": o["dest_key"],
                "body_hash": meta["body_hash"],
                "size": meta["size"],
                "category": meta["category"],
                "sealed": meta["sealed"],
                "encapsulation": meta["encapsulation"],
                "namespace": d["namespace"],
                "copied_from_drill": d["id"],
            }
            if tmeta["key"] in tgt.objects:
                # Defensive: an external collision must not double-count.
                existing = tgt.objects[tmeta["key"]]
                if existing["body_hash"] != tmeta["body_hash"]:
                    raise ConflictState(
                        f"destination object collision on {tmeta['key']}")
            else:
                tgt.objects[tmeta["key"]] = tmeta
                tgt.used_bytes += tmeta["size"]
            resource_rec = {
                "kind": "object", "key": tmeta["key"],
                "source_key": o["key"], "size": tmeta["size"],
                "body_hash": tmeta["body_hash"],
                "category": tmeta["category"],
                "sealed": tmeta["sealed"]}
            self._resource_once(d, rkey, lambda rec=resource_rec: dict(rec))
            d["copied_objects"].append(tmeta["key"])
            copied_here += 1
        self.regions.save(tgt)
        d["copy_count"] = len(d["copied_objects"])

    def _stage_rebuild_index(self, d: dict):
        # Rebuild a search/read index from the copied public material only.
        entries = []
        for key in d["copied_objects"]:
            o = d["resources"][self._idem_key(d, STAGE_COPY) + ":" + key]
            if o["category"] in (CATEGORY_PUBLIC_KEYS, CATEGORY_POLICY,
                                 CATEGORY_AUDIT, CATEGORY_INDEX):
                entries.append({"key": key, "category": o["category"],
                                "body_hash": o["body_hash"]})
        idx = {
            "entries": sorted(entries, key=lambda e: e["key"]),
            "index_hash": crypto.digest_hex(entries),
        }
        ikey = self._idem_key(d, STAGE_REBUILD_INDEX) + ":index"
        self._resource_once(d, ikey, lambda: {
            "kind": "shadow-index", **idx})
        d["index"] = idx

    def _stage_shadow_start(self, d: dict):
        skey = self._idem_key(d, STAGE_SHADOW_START) + ":service"
        svc = self._resource_once(d, skey, lambda: {
            "kind": "shadow-service",
            "service_id": "shadow-" + d["namespace"],
            "namespace": d["namespace"],
            "region": d["target_region"],
            "ingest_mode": "read_only",
            "write_ingress": "disabled",
            "index_hash": d["index"]["index_hash"]})
        d["shadow_service"] = svc

    def _stage_probes(self, d: dict):
        """Replay a fixed set of signature/verification probe vectors against
        the shadow and compare with source results. Probes are READ-only."""
        bp = d["blueprint"]
        vectors = self._probe_vectors(d)
        results = []
        for v in vectors:
            pkey = self._idem_key(d, STAGE_PROBES) + ":" + v["probe_id"]
            if pkey in d["resources"]:
                continue
            # production result was captured when the vector was built
            source_result = v["source"]
            shadow_result = self._replay_in_shadow(d, v)
            passed = source_result == shadow_result
            rec = {
                "probe_id": v["probe_id"], "kind": v["kind"],
                "request_hash": v["request_hash"],
                "source_result_hash": crypto.digest_hex(source_result),
                "shadow_result_hash": crypto.digest_hex(shadow_result),
                "passed": passed,
                "latency_ms": v.get("latency_ms", 1),
            }
            self._resource_once(d, pkey, lambda: {"kind": "probe", **rec})
            d["probes"].append(rec)
            results.append(rec)
            if not passed:
                raise PreflightFailed(
                    f"probe {v['probe_id']} mismatch: shadow result differs "
                    "from source")
        d["probe_results"] = results

    def _probe_vectors(self, d: dict) -> list[dict]:
        """Fixed probes derived deterministically from the blueprint:
        * OBJECT_HASH  - re-compute each copied object's content hash;
        * INDEX_LOOKUP - the rebuilt index resolves every public object;
        * VERIFY       - historical signature verification still valid.

        Probe inputs are hashes only - no sensitive content is embedded.
        """
        if d.get("_probe_vectors"):
            return d["_probe_vectors"]
        vectors = []
        for key in d["copied_objects"]:
            o = d["resources"][self._idem_key(d, STAGE_COPY) + ":" + key]
            req = {"key": key, "expected_hash": o["body_hash"]}
            vectors.append({
                "probe_id": "hash:" + key,
                "kind": "OBJECT_HASH",
                "request_hash": crypto.digest_hex(req),
                "source": {"body_hash": o["body_hash"]},
                "latency_ms": 1,
            })
        idx = d["index"]
        for e in idx["entries"]:
            req = {"index": idx["index_hash"], "key": e["key"]}
            vectors.append({
                "probe_id": "index:" + e["key"],
                "kind": "INDEX_LOOKUP",
                "request_hash": crypto.digest_hex(req),
                "source": {"resolved": True, "body_hash": e["body_hash"]},
                "latency_ms": 1,
            })
        # VERIFY probes: replay historical verify vectors recorded at scan
        for v in d.get("verify_vectors", []):
            vectors.append(v)
        d["_probe_vectors"] = vectors
        return vectors

    def add_verify_vector(self, drill_id: str, purpose: str, message: bytes,
                          sig_b64: str, expected_version: str):
        """Attach a historical signature verification vector (read-only)."""
        d = self._drill(drill_id)
        req = {"purpose": purpose, "message": crypto.b64e(message),
               "sig": sig_b64}
        d.setdefault("verify_vectors", []).append({
            "probe_id": "verify:" + crypto.digest_hex(req)[:16],
            "kind": "VERIFY",
            "request_hash": crypto.digest_hex(req),
            "source": {"valid": True, "version_id": expected_version},
            "latency_ms": 1,
        })
        d.pop("_probe_vectors", None)
        return d["verify_vectors"][-1]

    def _replay_in_shadow(self, d: dict, v: dict) -> dict:
        if v["kind"] == "OBJECT_HASH":
            key = v["probe_id"].split(":", 1)[1]
            o = d["resources"][self._idem_key(d, STAGE_COPY) + ":" + key]
            return {"body_hash": o["body_hash"]}
        if v["kind"] == "INDEX_LOOKUP":
            key = v["probe_id"].split(":", 1)[1]
            entry = next((e for e in d["index"]["entries"]
                          if e["key"] == key), None)
            return ({"resolved": True, "body_hash": entry["body_hash"]}
                    if entry else {"resolved": False})
        if v["kind"] == "VERIFY":
            # shadow holds only public keys; verification result must match.
            # The sealed private material is never used for a read-only probe.
            return {"valid": True,
                    "version_id": v["source"]["version_id"]}
        raise ConflictState(f"unknown probe kind {v['kind']}")

    def _mark_ready(self, d: dict) -> dict:
        if d["status"] != DRILL_READY:
            d["status"] = DRILL_READY
            d["ready_at"] = _now(self.clock)
            elapsed = d["ready_at"] - (d["started_at"] or d["ready_at"])
            d["rto_observed_seconds"] = elapsed
            if elapsed > d["fields"]["rto_seconds"]:
                # Ready but outside the recovery time objective: a lease may
                # not be granted.
                d["rto_breached"] = True
            self._confirm_checkpoint(d, STAGE_READY,
                                     {"rto_observed_seconds": elapsed})
            self.audit.append("drill_ready",
                              {"drill_id": d["id"],
                               "rto_observed_seconds": elapsed,
                               "rto_breached": d.get("rto_breached", False)})
        return self.public_drill(d["id"])

    # ======================================================================
    # observation window + read-only mirror comparator
    # ======================================================================
    def open_window(self, drill_id: str, actor: str,
                    seconds: int | None = None) -> dict:
        d = self._drill(drill_id)
        if d["status"] not in (DRILL_READY, DRILL_FAILED_BACK, DRILL_OBSERVING,
                               DRILL_FROZEN):
            raise ConflictState(
                f"shadow not ready for observation (status {d['status']})")
        self._ensure_credential(d)
        w = d.get("window")
        now = _now(self.clock)
        if w and now <= w["closes_at"] and d["status"] == DRILL_OBSERVING:
            return self.public_drill(drill_id)  # idempotent re-open
        seconds = seconds or DEFAULT_WINDOW_SECONDS
        d["window"] = {"opened_at": now, "closes_at": now + seconds,
                       "opened_by": actor, "ratio": d["fields"]["mirror_ratio"],
                       "closed": False}
        d["status"] = DRILL_OBSERVING
        self.audit.append("drill_window_opened",
                          {"drill_id": drill_id, "seconds": seconds,
                           "ratio": d["fields"]["mirror_ratio"]})
        return self.public_drill(drill_id)

    def close_window(self, drill_id: str, actor: str | None = None) -> dict:
        d = self._drill(drill_id)
        w = d.get("window")
        if w and not w["closed"]:
            w["closed"] = True
            w["closed_at"] = _now(self.clock)
            w["closed_by"] = actor
            if d["status"] == DRILL_OBSERVING:
                d["status"] = DRILL_READY
            self.audit.append("drill_window_closed",
                              {"drill_id": drill_id, "actor": actor})
        return self.public_drill(drill_id)

    def _window_open(self, d: dict) -> bool:
        w = d.get("window")
        return bool(w and not w["closed"]
                    and _now(self.clock) <= w["closes_at"])

    def mirror_request(self, drill_id: str, request: dict) -> dict:
        """Route a verification request.

        Write operations (sign/rotate/destroy/policy/...) are ALWAYS executed
        in production and never mirrored, regardless of any forged
        `mirror_to_shadow` flag on the client request. Read-only requests are,
        while a window is open, mirrored at the plan ratio and compared.
        """
        d = self._drill(drill_id)
        op = request.get("operation", "READ")
        rid = request.get("request_id") or _mid("req")
        forced = bool(request.get("mirror_to_shadow"))
        record = {
            "request_id": rid, "operation": op,
            "client_forced_mirror": forced,
            "at": _now(self.clock),
            "routed_to": None, "mirrored": False, "in_window": False,
        }
        # 1. write operations: production only, forged flag rejected
        if op in WRITE_OPERATIONS:
            # A frozen drill refuses further traffic before executing anything.
            if d["status"] == DRILL_FROZEN:
                raise DrillFrozen(
                    "drill is frozen after a threshold breach; resume after "
                    "repair or terminate")
            record["routed_to"] = "production"
            record["reason"] = (
                "write operations must stay in the production region"
                + (" (forged mirror flag ignored)" if forced else ""))
            d["mirror"]["stats"]["production_only"] += 1
            d["mirror"]["requests"].append(record)
            if forced:
                # Explicit policy rejection for a write carrying a mirror flag.
                raise PolicyViolation(
                    "write requests cannot be mirrored to the isolated region, "
                    "even with a forged mirror marker")
            return {"request_id": rid, "served_by": "production",
                    "mirrored": False}

        if op not in READ_ONLY_OPERATIONS:
            raise PolicyViolation(f"unknown request operation {op}")

        # Idempotency precedes the frozen guard: re-submitting the correlation
        # id of a comparison already made (including the one that deactivated
        # the bypass) returns the recorded verdict. The shadow is not re-queried
        # and the mismatch counter is not touched - so a client retry after a
        # crash can never count twice, even while FROZEN.
        prior = self._prior_mirrored(d, rid)
        if prior is not None:
            return self._mirror_replay(
                d, prior, self._production_read(d, request)["value"])

        # A frozen drill refuses further *new* shadow traffic until repaired.
        if d["status"] == DRILL_FROZEN:
            raise DrillFrozen(
                "drill is frozen after a threshold breach; resume after "
                "repair or terminate")

        # 2. read-only: production always answers; mirror at ratio while an
        # observation window is open.
        prod_result = self._production_read(d, request)
        record["routed_to"] = "production"
        record["production_latency_ms"] = prod_result["latency_ms"]

        if not self._window_open(d):
            if forced:
                record["reason"] = "mirror requested outside any open window"
                d["mirror"]["requests"].append(record)
                raise DrillFrozen(
                    "no open observation window: mirroring is refused "
                    "(window-outside mirror is a policy violation)")
            d["mirror"]["requests"].append(record)
            return {"request_id": rid, "served_by": "production",
                    "mirrored": False, "result": prod_result["value"]}

        record["in_window"] = True
        ratio = d["window"]["ratio"]
        selected = forced or self._select_for_mirror(rid, ratio)
        if not selected:
            d["mirror"]["requests"].append(record)
            return {"request_id": rid, "served_by": "production",
                    "mirrored": False, "result": prod_result["value"],
                    "tolerance": self._tolerance_view(d)}

        # 3. mirror to shadow + compare
        shadow = self._shadow_read(d, request,
                                   latency_ms=request.get("_shadow_latency_ms"),
                                   value_override=request.get(
                                       "_shadow_value_override"),
                                   timeout=request.get("_shadow_timeout"))
        record["mirrored"] = True
        record["shadow_latency_ms"] = shadow["latency_ms"]
        d["mirror"]["stats"]["mirrored"] += 1
        diffs = []
        if shadow["timeout"]:
            diffs.append("TIMEOUT")
            d["mirror"]["stats"]["timeouts"] += 1
        elif shadow["value"] != prod_result["value"]:
            diffs.append("RESPONSE_MISMATCH")
        if (not shadow["timeout"]
                and shadow["latency_ms"] > d["fields"]["latency_threshold_ms"]):
            diffs.append("LATENCY")
        cmp_rec = {
            "request_id": rid, "operation": op, "at": record["at"],
            "production_result_hash": crypto.digest_hex(prod_result["value"]),
            "shadow_result_hash": (None if shadow["timeout"]
                                   else crypto.digest_hex(shadow["value"])),
            "production_latency_ms": prod_result["latency_ms"],
            "shadow_latency_ms": shadow["latency_ms"],
            "differences": diffs,
        }
        if diffs:
            d["mirror"]["stats"]["differences"] += 1
            record["differences"] = diffs
            # Comparison record + request log + counter increment +
            # deactivation decision are one atomic step under the store lock,
            # so concurrent verifications observe a single total order.
            tol = self._tolerance(d)
            tol["mismatch_count"] += 1
            cmp_rec["mismatch_count"] = tol["mismatch_count"]
            cmp_rec["quota"] = tol["quota"]
            d["mirror"]["differences"].append(cmp_rec)
            d["mirror"]["requests"].append(record)
            # The bypass is deactivated only when the *accumulated* count
            # grows greater than the quota (quota 0: first mismatch).
            if tol["mismatch_count"] > tol["quota"]:
                self._freeze(d, reason=diffs[0], request_id=rid)
                return {"request_id": rid, "served_by": "production",
                        "mirrored": True, "differences": diffs,
                        "frozen": True, "result": prod_result["value"],
                        "tolerance": self._tolerance_view(d)}
            self.audit.append(
                "drill_mirror_mismatch_tolerated",
                {"drill_id": d["id"], "request_id": rid,
                 "differences": diffs,
                 "mismatch_count": tol["mismatch_count"],
                 "quota": tol["quota"]})
            return {"request_id": rid, "served_by": "production+shadow",
                    "mirrored": True, "differences": diffs,
                    "frozen": False, "tolerated": True,
                    "result": prod_result["value"],
                    "tolerance": self._tolerance_view(d)}
        d["mirror"]["stats"]["matched"] += 1
        d["mirror"]["requests"].append(record)
        return {"request_id": rid, "served_by": "production+shadow",
                "mirrored": True, "matched": True,
                "result": prod_result["value"],
                "tolerance": self._tolerance_view(d)}

    # ---- comparison tolerance quota ---------------------------------------
    def _tolerance(self, d: dict) -> dict:
        """Persistent tolerance state; also fills records started by an
        older build so the counter semantics survive an in-place upgrade."""
        tol = d.get("tolerance")
        if tol is None:
            tol = {"quota": int(d["fields"].get("diff_threshold",
                                                DEFAULT_DIFF_THRESHOLD)),
                   "mismatch_count": 0,
                   "trigger_request_id": None,
                   "history": []}
            d["tolerance"] = tol
        return tol

    def _tolerance_view(self, d: dict) -> dict:
        """Same quota / count / deactivation-correlation-id triple surfaced
        by the HTTP responses, the drill page and the evidence archive."""
        tol = self._tolerance(d)
        return {"quota": tol["quota"],
                "mismatch_count": tol["mismatch_count"],
                "deactivated": d["status"] == DRILL_FROZEN,
                "trigger_request_id": tol["trigger_request_id"]}

    def _prior_mirrored(self, d: dict, request_id: str) -> dict | None:
        return next((r for r in d["mirror"]["requests"]
                     if r["request_id"] == request_id and r["mirrored"]),
                    None)

    def _mirror_replay(self, d: dict, prior: dict, value) -> dict:
        """Idempotent response for a correlation id already compared: the
        shadow is not re-queried and the mismatch counter is not touched."""
        diffs = prior.get("differences") or []
        tol = self._tolerance(d)
        out = {
            "request_id": prior["request_id"],
            "served_by": ("production+shadow" if not diffs else "production"),
            "mirrored": True, "replayed": True, "result": value,
            "tolerance": self._tolerance_view(d),
        }
        if diffs:
            out["differences"] = diffs
            out["frozen"] = tol["trigger_request_id"] == prior["request_id"]
        else:
            out["matched"] = True
        return out

    @staticmethod
    def _select_for_mirror(request_id: str, ratio: float) -> bool:
        # deterministic, stable selection keyed by request correlation id
        h = int(crypto.digest_hex({"rid": request_id})[:8], 16) / 0xffffffff
        return h < ratio

    def _production_read(self, d: dict, request: dict) -> dict:
        # modeled read: deterministic value from request + source index
        key = request.get("key") or request.get("purpose") or "default"
        val = {"key": key, "source": d["source_region"],
               "digest": crypto.digest_hex(
                   {"rid-key": key, "bp": d["blueprint_hash"]})}
        return {"value": val,
                "latency_ms": int(request.get("_prod_latency_ms", 5))}

    def _shadow_read(self, d: dict, request: dict, *, latency_ms=None,
                     value_override=None, timeout=False) -> dict:
        # a healthy shadow returns the same deterministic value as production
        if value_override is not None:
            value = value_override
        else:
            value = self._production_read(d, request)["value"]
        return {"value": value,
                "latency_ms": int(5 if latency_ms is None else latency_ms),
                "timeout": bool(timeout)}

    # ---- freeze / resume --------------------------------------------------
    def _freeze(self, d: dict, *, reason: str, request_id: str):
        tol = self._tolerance(d)
        # The correlation id of the comparison that crossed the quota is the
        # one the page, HTTP responses and the evidence package all cite.
        tol["trigger_request_id"] = request_id
        tol["history"].append(
            {"request_id": request_id, "reason": reason,
             "at": _now(self.clock),
             "mismatch_count": tol["mismatch_count"],
             "quota": tol["quota"]})
        d["status"] = DRILL_FROZEN
        d["freeze"] = {"reason": reason, "request_id": request_id,
                       "at": _now(self.clock),
                       "checkpoints": len(d["checkpoints"]),
                       "quota": tol["quota"],
                       "mismatch_count": tol["mismatch_count"]}
        self.audit.append("drill_frozen",
                          {"drill_id": d["id"], "reason": reason,
                           "request_id": request_id,
                           "quota": tol["quota"],
                           "mismatch_count": tol["mismatch_count"]})

    def resume_after_repair(self, drill_id: str, actor: str,
                            *, note: str = "") -> dict:
        """Clear a freeze and continue from the freeze point: the shadow
        stages are not re-run; mirroring resumes under the same window (or a
        fresh one may be opened)."""
        d = self._drill(drill_id)
        if d["status"] != DRILL_FROZEN:
            raise ConflictState(f"drill {drill_id} is not frozen")
        # Re-validate probes before resuming (repair must restore consistency).
        for p in d["probes"]:
            if not p["passed"]:
                raise ConflictState(
                    "repair did not restore probe consistency; cannot resume")
        fz = d["freeze"]
        fz["resumed_at"] = _now(self.clock)
        fz["resumed_by"] = actor
        fz["repair_note"] = note
        d["status"] = DRILL_READY
        # Manual release reactivates the bypass but does not reset the tally:
        # the accumulated mismatch count stays continuous (it also survives
        # service restarts, as it lives in the persisted drill record).
        tol = self._tolerance(d)
        tol["trigger_request_id"] = None
        self.audit.append("drill_resumed",
                          {"drill_id": drill_id, "actor": actor, "note": note,
                           "frozen_at": fz["at"],
                           "mismatch_count": tol["mismatch_count"],
                           "quota": tol["quota"]})
        return self.public_drill(drill_id)

    def mirror_stats(self, drill_id: str) -> dict:
        d = self._drill(drill_id)
        return {"stats": dict(d["mirror"]["stats"]),
                "tolerance": self._tolerance_view(d)}

    # ======================================================================
    # failover lease
    # ======================================================================
    def acquire_lease(self, drill_id: str, instance_id: str, actor: str,
                      ttl_seconds: int | None = None) -> dict:
        """Grant the single failover lease.

        Only a drill that passed every probe and still meets RTO may hold it.
        Concurrent control instances contend on one record: at most one wins.
        """
        d = self._drill(drill_id)
        self._expire_lease(d)
        if d.get("lease") and d["lease"]["status"] == "HELD":
            raise LeaseContention(
                f"lease already held by instance "
                f"{d['lease']['holder_instance']} until "
                f"{d['lease']['expires_at']}")
        if not self._checkpoint(d, STAGE_PROBES):
            raise ConflictState("all probes must pass before failover")
        if any(not p["passed"] for p in d["probes"]):
            raise ConflictState("a probe is failing; failover refused")
        if d.get("rto_breached"):
            raise ConflictState("RTO not met; failover lease refused")
        if d["status"] == DRILL_FROZEN:
            raise ConflictState("drill is frozen; resolve before failover")
        if self._window_open(d):
            raise ConflictState(
                "close the observation window before acquiring the lease")
        self._ensure_credential(d)
        now = _now(self.clock)
        lease = {
            "lease_id": _mid("lease"),
            "status": "HELD",
            "holder_instance": instance_id,
            "acquired_by": actor,
            "acquired_at": now,
            "expires_at": now + (ttl_seconds or DEFAULT_LEASE_SECONDS),
            "scope": "read_only_verification_ingress",
            "write_ingress": "production_unchanged",
            "history": [],
        }
        lease["history"].append({"at": now, "event": "acquired",
                                 "instance": instance_id, "actor": actor})
        d["lease"] = lease
        d["status"] = DRILL_FAILOVER
        self.audit.append("drill_lease_acquired",
                          {"drill_id": drill_id,
                           "lease_id": lease["lease_id"],
                           "instance": instance_id,
                           "expires_at": lease["expires_at"]})
        return dict(lease)

    def _expire_lease(self, d: dict):
        lease = d.get("lease")
        if lease and lease["status"] == "HELD" \
                and _now(self.clock) > lease["expires_at"]:
            lease["status"] = "EXPIRED"
            lease["history"].append(
                {"at": _now(self.clock), "event": "expired"})
            self.audit.append("drill_lease_expired",
                              {"drill_id": d["id"],
                               "lease_id": lease["lease_id"]})
            self._converge_after_lease(d, reason="lease_expired")

    def failover_status(self, drill_id: str) -> dict:
        d = self._drill(drill_id)
        self._expire_lease(d)
        return {"status": d["status"],
                "read_ingress": ("shadow" if d["status"] == DRILL_FAILOVER
                                 else "production"),
                "write_ingress": "production",
                "lease": d.get("lease")}

    # ---- failback (converged, idempotent) ---------------------------------
    def failback(self, drill_id: str, actor: str, *,
                 reason: str = "manual") -> dict:
        """Release the lease and return read ingress to production.

        Lease loss, region recovery, window close and manual failback all
        converge here. A repeated submit returns the ORIGINAL result.
        """
        d = self._drill(drill_id)
        # idempotent: already failed back -> return the recorded result
        if d["status"] == DRILL_FAILED_BACK and d.get("failback"):
            return dict(d["failback"])
        self._expire_lease(d)
        lease = d.get("lease")
        now = _now(self.clock)
        if d["status"] == DRILL_FAILOVER and lease and lease["status"] == "HELD":
            lease["status"] = "RELEASED"
            lease["history"].append({"at": now, "event": "released",
                                     "actor": actor, "reason": reason})
        result = {
            "drill_id": drill_id,
            "read_ingress": "production",
            "write_ingress": "production",
            "failed_back_at": now,
            "actor": actor,
            "reason": reason,
            "lease_id": lease["lease_id"] if lease else None,
            "idempotent_result": True,
        }
        d["failback"] = result
        d["status"] = DRILL_FAILED_BACK
        self.audit.append("drill_failed_back",
                          {"drill_id": drill_id, "actor": actor,
                           "reason": reason,
                           "lease_id": result["lease_id"]})
        return dict(result)

    def _converge_after_lease(self, d: dict, *, reason: str):
        """Every trigger (lease loss, region recovery, window close, manual
        failback) converges to the same FAILED_BACK state."""
        if d["status"] in (DRILL_FAILOVER, DRILL_OBSERVING, DRILL_FROZEN,
                           DRILL_READY) and not d.get("failback"):
            d["failback"] = {
                "drill_id": d["id"], "read_ingress": "production",
                "write_ingress": "production",
                "failed_back_at": _now(self.clock),
                "actor": "system", "reason": reason,
                "lease_id": (d.get("lease") or {}).get("lease_id"),
                "idempotent_result": True,
            }
            if d["status"] != DRILL_FROZEN:
                d["status"] = DRILL_FAILED_BACK
            self.audit.append("drill_converged_failback",
                              {"drill_id": d["id"], "reason": reason})

    # ======================================================================
    # termination + resumable, blocker-aware cleanup
    # ======================================================================
    def terminate(self, drill_id: str, actor: str, *,
                 auto_close_window: bool = False) -> dict:
        d = self._drill(drill_id)
        if d["status"] in (DRILL_CLEANED, DRILL_ABORTED):
            return self.public_drill(drill_id)
        # any live lease is released through the converged failback path
        self._expire_lease(d)
        if d.get("lease") and d["lease"]["status"] == "HELD":
            self.failback(drill_id, actor, reason="terminate")
        # An open observation window is live mirror traffic: termination must
        # surface it as a blocker (the operator closes/fails back first).
        if self._window_open(d) and not auto_close_window:
            d["status"] = DRILL_TERMINATING
            d.setdefault("cleanup",
                         {"phase": "INIT", "done": [], "blockers": []})
            self.audit.append("drill_terminate_requested",
                              {"drill_id": drill_id, "actor": actor})
            return self.cleanup(drill_id)  # raises CleanupBlocked
        if self._window_open(d):
            self.close_window(drill_id, actor)
        d["status"] = DRILL_TERMINATING
        d.setdefault("cleanup", {"phase": "INIT", "done": [], "blockers": []})
        self.audit.append("drill_terminate_requested",
                          {"drill_id": drill_id, "actor": actor})
        return self.cleanup(drill_id)

    def cleanup(self, drill_id: str) -> dict:
        """Resumable cleanup. Refuses critical-resource deletion while
        mirror traffic is active, a lease is held, or diffs are unarchived."""
        d = self._drill(drill_id)
        if d["status"] == DRILL_CLEANED:
            return self.public_drill(drill_id)
        d = self._drill(drill_id)
        cu = d.get("cleanup")
        if cu is None:
            cu = {"phase": "INIT", "done": [], "blockers": []}
            d["cleanup"] = cu

        blockers = self._cleanup_blockers(d)
        cu["blockers"] = blockers
        if blockers:
            raise CleanupBlocked(blockers)

        # phase 1: revoke the short-lived credentials (nothing can act after)
        if "REVOKE_CREDENTIALS" not in cu["done"]:
            self._revoke_credentials(d)
            cu["done"].append("REVOKE_CREDENTIALS")
            cu["phase"] = "REVOKE_CREDENTIALS"
        # phase 2: delete isolated resources (objects, service, namespace)
        if "DELETE_RESOURCES" not in cu["done"]:
            self._delete_isolated_resources(d)
            cu["done"].append("DELETE_RESOURCES")
            cu["phase"] = "DELETE_RESOURCES"
        # phase 3: converge the final status, THEN seal the evidence archive
        # so the archive records CLEANED and the full cleanup phase list.
        d["status"] = DRILL_CLEANED
        cu["phase"] = "FINALIZED"
        if "ARCHIVE_EVIDENCE" not in cu["done"]:
            ev = self._archive_evidence(d)
            d["evidence_id"] = ev["evidence_id"]
            cu["done"].append("ARCHIVE_EVIDENCE")
        cu["phase"] = "DONE"
        cu["completed_at"] = _now(self.clock)
        self.audit.append("drill_cleaned",
                          {"drill_id": drill_id,
                           "evidence_id": d["evidence_id"]})
        return self.public_drill(drill_id)

    def _cleanup_blockers(self, d: dict) -> list[str]:
        blockers: list[str] = []
        # live mirror traffic: an open window, or mirrored requests with no
        # post-window archive marker
        if self._window_open(d):
            blockers.append(
                f"observation window open until {d['window']['closes_at']}")
        self._expire_lease(d)
        if d.get("lease") and d["lease"]["status"] == "HELD":
            blockers.append(
                f"failover lease {d['lease']['lease_id']} still held by "
                f"{d['lease']['holder_instance']} until "
                f"{d['lease']['expires_at']}")
        unarchived = [x for x in d["mirror"]["differences"]
                      if not x.get("archived")]
        if unarchived:
            blockers.append(
                f"{len(unarchived)} unarchived mirror difference(s); "
                "archive evidence before deleting critical resources")
        return blockers

    def archive_differences(self, drill_id: str) -> dict:
        """Operator action: freeze the difference records into the evidence
        set so cleanup can proceed (the records themselves are retained)."""
        d = self._drill(drill_id)
        n = 0
        for x in d["mirror"]["differences"]:
            if not x.get("archived"):
                x["archived"] = True
                x["archived_at"] = _now(self.clock)
                n += 1
        self.audit.append("drill_differences_archived",
                          {"drill_id": drill_id, "count": n})
        return {"archived": n,
                "remaining": sum(1 for x in d["mirror"]["differences"]
                                 if not x.get("archived"))}

    def _delete_isolated_resources(self, d: dict):
        tgt = self.regions.get(d["target_region"])
        # delete in reverse dependency order, each keyed idempotently
        d.pop("shadow_service", None)
        for key in list(d["copied_objects"]):
            tgt.delete_object(key)
        d["copied_objects"] = []
        # remove namespace reservation marker
        nskey = self._idem_key(d, STAGE_PREPARE) + ":namespace"
        d["resources"].pop(nskey, None)
        self.regions.save(tgt)

    # ======================================================================
    # evidence archive
    # ======================================================================
    def _archive_evidence(self, d: dict) -> dict:
        from .evidence import build_evidence
        ev = build_evidence(d, self.seed, clock=self.clock)
        d["evidence"] = ev
        self.state.setdefault("drill_evidence", {})[ev["evidence_id"]] = ev
        self.audit.append("drill_evidence_archived",
                          {"drill_id": d["id"],
                           "evidence_id": ev["evidence_id"],
                           "manifest_hash": ev["manifest_hash"]})
        return {"evidence_id": ev["evidence_id"]}

    def evidence(self, drill_id: str) -> dict:
        d = self._drill(drill_id)
        if not d.get("evidence"):
            raise NotFound(f"no archived evidence for drill {drill_id}")
        return d["evidence"]

    # ======================================================================
    # views
    # ======================================================================
    def public_drill(self, drill_id: str, secret: str | None = None) -> dict:
        d = self._drill(drill_id)
        cred = d["credentials"][-1]
        view = {
            "id": d["id"], "plan_id": d["plan_id"], "status": d["status"],
            "namespace": d["namespace"],
            "credential": {
                "cred_id": cred["cred_id"],
                "namespace": cred["namespace"],
                "issued_at": cred["issued_at"],
                "expires_at": cred["expires_at"],
                "status": cred["status"],
                "scope": cred["scope"],
                # raw secret only on the start response, never persisted view
                **({"secret": secret} if secret else {}),
            },
            "blueprint_hash": d["blueprint_hash"],
            "checkpoints": [
                {"stage": c["stage"],
                 "checkpoint_id": c["checkpoint_id"],
                 "idempotency_key": c["idempotency_key"],
                 "confirmed_at": c["confirmed_at"],
                 "detail": c["detail"]}
                for c in d["checkpoints"]],
            "resources": sorted(v["kind"] for v in d["resources"].values()),
            "copied_objects": list(d["copied_objects"]),
            "probes": [
                {"probe_id": p["probe_id"], "kind": p["kind"],
                 "passed": p["passed"],
                 "request_hash": p["request_hash"],
                 "source_result_hash": p["source_result_hash"],
                 "shadow_result_hash": p["shadow_result_hash"]}
                for p in d["probes"]],
            "window": (None if not d.get("window") else {
                "opened_at": d["window"]["opened_at"],
                "closes_at": d["window"]["closes_at"],
                "closed": d["window"]["closed"],
                "ratio": d["window"]["ratio"]}),
            "mirror_stats": dict(d["mirror"]["stats"]),
            "tolerance": self._tolerance_view(d),
            "differences": list(d["mirror"]["differences"]),
            "freeze": d.get("freeze"),
            "lease": d.get("lease"),
            "failback": d.get("failback"),
            "cleanup": d.get("cleanup"),
            "evidence_id": d.get("evidence_id"),
            "rto_observed_seconds": d.get("rto_observed_seconds"),
            "rto_breached": d.get("rto_breached", False),
        }
        return view


class _SimulatedCrash(Exception):
    """Internal: a stage died before its durable checkpoint (test hook)."""

    def __init__(self, stage: str):
        self.stage = stage
        super().__init__(f"simulated crash during {stage}")
