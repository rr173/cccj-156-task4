"""Simulated regional infrastructure for cross-region disaster drills.

A real deployment separates regions at the network/storage/control plane.
Drills must exercise the real boundary properties (credentials scoped to a
namespace, content-addressed objects, capacity, isolation policy) without
requiring a second datacenter in the reference implementation. This module
models those properties in-process:

Region
    * `objects`:      object_key -> {body_hash, size, sealed, category, ...}
                      The *body* of an object is intentionally never stored
                      here when it represents root material: only a
                      content-addressed hash and a sealed blob reference.
    * `capacity`/`used_bytes`: capacity gating before an isolated rebuild.
    * `isolation`:    required target isolation policy (network egress,
                      no production credentials, namespace prefix).
    * `config_seq`:   bumped on every target configuration change; the
                      preflight blueprint pins the sequence it scanned.
    * namespaces:     production objects live under `prod/`; drill-created
                      resources live under an isolated `drill-<id>/`
                      namespace and short-lived credential that production
                      requests cannot reference.

The registry persists inside the main store state so crash/restart tests
exercise real recovery. Nothing here unwraps root material.
"""

from __future__ import annotations

import hashlib
import os

from . import crypto
from .errors import PolicyViolation

PROD_NAMESPACE = "prod"

# Object categories a recovery point is allowed to contain. A drill plan
# whitelists which of them the isolated rebuild may restore.
CATEGORY_KEY_MATERIAL = "key_material"      # sealed wraps only (never plaintext)
CATEGORY_PUBLIC_KEYS = "public_keys"
CATEGORY_AUDIT = "audit"
CATEGORY_INDEX = "index"
CATEGORY_POLICY = "policy"
CATEGORY_SESSIONS = "sessions"              # never restorable into a drill
RECOVERABLE_CATEGORIES = (
    CATEGORY_KEY_MATERIAL, CATEGORY_PUBLIC_KEYS, CATEGORY_AUDIT,
    CATEGORY_INDEX, CATEGORY_POLICY,
)
# Categories that must never be mirrored/restored into an isolated region.
NEVER_RESTORABLE = (CATEGORY_SESSIONS,)

ISOLATION_AIRGAPPED = "AIRGAPPED"           # no egress, no prod creds
ISOLATION_RESTRICTED = "RESTRICTED_EGRESS"  # egress to verification net only
ISOLATION_LEVELS = (ISOLATION_AIRGAPPED, ISOLATION_RESTRICTED)

REQUIRED_ISOLATION = ISOLATION_AIRGAPPED


def _hash_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class Region:
    def __init__(self, name: str, *, isolated: bool = False,
                 capacity: int = 1 << 30, isolation: str = ISOLATION_AIRGAPPED,
                 egress: str = "none"):
        self.name = name
        self.isolated = isolated
        self.capacity = capacity
        self.used_bytes = 0
        # object_key -> object metadata dict
        self.objects: dict[str, dict] = {}
        # recovery_point_id -> manifest dict (source region only)
        self.recovery_points: dict[str, dict] = {}
        self.isolation_policy = {
            "level": isolation,
            "network_egress": egress,
            "allow_production_credentials": False,
            "require_namespace_prefix": "drill-" if isolated else "",
        }
        self.config_seq = 1
        # dependency versions actually deployed in this region
        self.dependencies = {
            "kc-core": "1.4.0",
            "verify-engine": "2.1.0",
            "enclave-image": "3.0.7",
        }

    # ---- configuration (changes bump config_seq; invalidates blueprints) --
    def update_config(self, **changes) -> dict:
        if "isolation" in changes:
            self.isolation_policy["level"] = changes["isolation"]
        if "egress" in changes:
            self.isolation_policy["network_egress"] = changes["egress"]
        if "capacity" in changes:
            self.capacity = int(changes["capacity"])
        if "dependencies" in changes:
            self.dependencies.update(changes["dependencies"])
        self.config_seq += 1
        return self.config_summary()

    def config_summary(self) -> dict:
        return {
            "region": self.name,
            "isolated": self.isolated,
            "capacity": self.capacity,
            "used_bytes": self.used_bytes,
            "available_bytes": self.capacity - self.used_bytes,
            "isolation_policy": dict(self.isolation_policy),
            "dependencies": dict(self.dependencies),
            "config_seq": self.config_seq,
        }

    # ---- objects ----------------------------------------------------------
    def put_object(self, key: str, body: bytes, category: str, *,
                   sealed: bool = False, recovery_point: str | None = None,
                   encapsulation: dict | None = None,
                   namespace: str = PROD_NAMESPACE,
                   sensitive: bool = False) -> dict:
        if "/" not in key:
            key = namespace + "/" + key
        if key in self.objects:
            raise PolicyViolation(f"object {key} already exists")
        meta = {
            "key": key,
            "body_hash": _hash_bytes(body),
            "size": len(body),
            "category": category,
            "sealed": bool(sealed),
            "sensitive": bool(sensitive),
            "recovery_point": recovery_point,
            # encapsulation descriptor: algorithm + wrapping key id. The
            # reference model treats *all* key_material objects as sealed
            # blobs; the drill engine copies the descriptor without unwrap.
            "encapsulation": encapsulation or (
                {"alg": "kc-aead-v1", "wrapped_by": "service-wrap"}
                if sealed else None),
            "namespace": namespace,
        }
        self.objects[key] = meta
        self.used_bytes += meta["size"]
        return meta

    def has_object(self, key: str) -> bool:
        return key in self.objects

    def object_meta(self, key: str) -> dict:
        return self.objects[key]

    def delete_object(self, key: str) -> bool:
        meta = self.objects.pop(key, None)
        if meta:
            self.used_bytes -= meta["size"]
        return meta is not None

    def objects_in_namespace(self, namespace: str) -> list[dict]:
        return [m for m in self.objects.values()
                if m["key"].startswith(namespace.rstrip("/") + "/")]

    # ---- recovery points (snapshot manifests) -----------------------------
    def create_recovery_point(self, rp_id: str, object_keys: list[str],
                              *, dependency_versions: dict | None = None,
                              note: str = "") -> dict:
        entries = []
        for k in object_keys:
            if k not in self.objects:
                raise PolicyViolation(
                    f"recovery point {rp_id} references missing object {k}")
            m = self.objects[k]
            entries.append({
                "key": k,
                "body_hash": m["body_hash"],
                "size": m["size"],
                "category": m["category"],
                "sealed": m["sealed"],
                "encapsulation": m["encapsulation"],
            })
        manifest = {
            "id": rp_id,
            "region": self.name,
            "created_seq": self.config_seq,
            "dependency_versions": dict(dependency_versions or self.dependencies),
            "objects": sorted(entries, key=lambda e: e["key"]),
            "manifest_hash": "",
            "note": note,
        }
        manifest["manifest_hash"] = crypto.digest_hex(
            {k: v for k, v in manifest.items() if k != "manifest_hash"})
        self.recovery_points[rp_id] = manifest
        return manifest

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "isolated": self.isolated,
            "capacity": self.capacity,
            "used_bytes": self.used_bytes,
            "objects": self.objects,
            "recovery_points": self.recovery_points,
            "isolation_policy": self.isolation_policy,
            "dependencies": self.dependencies,
            "config_seq": self.config_seq,
        }

    @staticmethod
    def from_dict(d: dict) -> "Region":
        r = Region(d["name"], isolated=d.get("isolated", False),
                   capacity=d.get("capacity", 1 << 30))
        r.used_bytes = d.get("used_bytes", 0)
        r.objects = dict(d.get("objects", {}))
        r.recovery_points = dict(d.get("recovery_points", {}))
        r.isolation_policy = dict(d.get("isolation_policy",
                                        r.isolation_policy))
        r.dependencies = dict(d.get("dependencies", r.dependencies))
        r.config_seq = d.get("config_seq", 1)
        return r


class RegionRegistry:
    """All region registries, persisted inside the store state dict."""

    def __init__(self, state: dict):
        self.state = state
        if "drill_regions" not in self.state:
            self.state["drill_regions"] = {}

    def define(self, name: str, *, isolated: bool = False,
               capacity: int = 1 << 30,
               isolation: str = ISOLATION_AIRGAPPED,
               egress: str = "none") -> Region:
        if name in self.state["drill_regions"]:
            raise PolicyViolation(f"region {name} already defined")
        r = Region(name, isolated=isolated, capacity=capacity,
                   isolation=isolation, egress=egress)
        self.state["drill_regions"][name] = r.to_dict()
        return r

    def get(self, name: str) -> Region:
        d = self.state["drill_regions"].get(name)
        if d is None:
            raise KeyError(name)
        return Region.from_dict(d)

    def save(self, region: Region):
        self.state["drill_regions"][region.name] = region.to_dict()

    def names(self) -> list[str]:
        return sorted(self.state["drill_regions"].keys())
