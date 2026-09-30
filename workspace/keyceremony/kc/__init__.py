"""kc - key management ceremony orchestration system.

Public surface:
    Orchestrator, Store, DeviceWallet, Policy, error types, ceremony/role constants.
"""

from . import authz, crypto, drills, ed25519, evidence, policy, regions, sessions
from .attestation import DeviceWallet, EnrolledDevice, provision_device
from .authz import Authz
from .ceremony import Orchestrator
from .directory import KeyDirectory
from .drills import DrillsManager
from .errors import (
    AttestationError, AuthenticationError, BlueprintStale, CeremonyError,
    CleanupBlocked, ComplementaryDutyConflict, ConflictState, DrillFrozen,
    DuplicateAction, EvidenceError, Forbidden, LeaseContention, NotFound,
    PayloadDrift, PolicyViolation, PreflightFailed, ProtectedOperation,
    QuorumFailure, RaceLost, ReplayError, RevisionConflict, SealError,
    TamperError, TargetStateChanged, TicketClosed,
)
from .regions import Region, RegionRegistry
from .sessions import SessionManager
from .storage import AuditLog, Store

__all__ = [
    "Orchestrator", "Store", "AuditLog", "KeyDirectory",
    "DeviceWallet", "EnrolledDevice", "provision_device",
    "SessionManager", "Authz",
    "DrillsManager", "Region", "RegionRegistry",
    "authz", "sessions", "crypto", "drills", "evidence", "regions",
    "ed25519", "policy",
    "CeremonyError", "ConflictState", "PolicyViolation", "AttestationError",
    "AuthenticationError", "Forbidden", "ProtectedOperation",
    "DuplicateAction", "ReplayError", "QuorumFailure",
    "SealError", "TamperError", "NotFound", "RaceLost",
    "TicketClosed", "PayloadDrift", "ComplementaryDutyConflict",
    "TargetStateChanged",
    "RevisionConflict", "PreflightFailed", "BlueprintStale", "DrillFrozen",
    "LeaseContention", "CleanupBlocked", "EvidenceError",
]
