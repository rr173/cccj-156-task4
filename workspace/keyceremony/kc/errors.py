"""Typed errors for the ceremony orchestrator."""


class CeremonyError(Exception):
    code = "CEREMONY_ERROR"
    http_status = 400

    def __init__(self, message: str = "", code: str | None = None):
        super().__init__(message or self.__class__.__doc__ or self.code)
        if code:
            self.code = code


class NotFound(CeremonyError):
    code = "NOT_FOUND"
    http_status = 404


class ConflictState(CeremonyError):
    """Ceremony or key is not in the required state for this action."""

    code = "CONFLICT_STATE"
    http_status = 409


class PolicyViolation(CeremonyError):
    """Fixed roles, threshold or quorum rules would be broken."""

    code = "POLICY_VIOLATION"
    http_status = 422


class AttestationError(CeremonyError):
    """Device quote failed: signature, measurement or replay checks."""

    code = "ATTESTATION_FAILED"
    http_status = 401


class AuthenticationError(CeremonyError):
    code = "AUTH_FAILED"
    http_status = 401


class Forbidden(CeremonyError):
    """Authenticated, but the duty bound to the token may not do this."""

    code = "FORBIDDEN"
    http_status = 403


class ProtectedOperation(CeremonyError):
    """The HTTP surface requires a four-eyes authorization ticket for this op.

    The underlying orchestrator library remains directly callable; only the
    web/API path is gated.
    """

    code = "PROTECTED_OPERATION"
    http_status = 422


class TicketClosed(CeremonyError):
    """The authorization ticket is no longer open (executed/withdrawn/closed)."""

    code = "TICKET_CLOSED"
    http_status = 409


class PayloadDrift(CeremonyError):
    """The approval does not match the frozen normalized payload digest."""

    code = "PAYLOAD_DRIFT"
    http_status = 409


class ComplementaryDutyConflict(CeremonyError):
    """Approver is not a complementary duty / is the same person or terminal."""

    code = "COMPLEMENTARY_DUTY_CONFLICT"
    http_status = 409


class TargetStateChanged(CeremonyError):
    """The guarded target moved between ticket creation and approval."""

    code = "TARGET_STATE_CHANGED"
    http_status = 409


class DuplicateAction(CeremonyError):
    """A different action for this slot/stage was already recorded."""

    code = "DUPLICATE_ACTION"
    http_status = 409


class ReplayError(CeremonyError):
    """This nonce has already been spent."""

    code = "REPLAY_DETECTED"
    http_status = 409


class QuorumFailure(CeremonyError):
    code = "QUORUM_NOT_MET"
    http_status = 422


class SealError(CeremonyError):
    code = "SEAL_FAILED"
    http_status = 400


class TamperError(CeremonyError):
    """Tamper-evident audit chain failed verification."""

    code = "TAMPER_DETECTED"
    http_status = 409


class RaceLost(CeremonyError):
    """Another activation/publish committed first; retry against the new state."""

    code = "RACE_LOST"
    http_status = 409


# ---------------------------------------------------------------------------
# cross-region disaster recovery drills
# ---------------------------------------------------------------------------

class RevisionConflict(CeremonyError):
    """The drill plan revision used to build the change is no longer current."""

    code = "REVISION_CONFLICT"
    http_status = 409

    def __init__(self, message: str = "", code: str | None = None,
                 *, base_revision: int | None = None,
                 current_revision: int | None = None,
                 base_snapshot: dict | None = None,
                 current_snapshot: dict | None = None):
        super().__init__(message, code)
        self.base_revision = base_revision
        self.current_revision = current_revision
        self.base_snapshot = base_snapshot
        self.current_snapshot = current_snapshot

    def details(self) -> dict:
        """Machine-readable conflict details for the two editing browsers."""
        return {
            "error": self.code,
            "message": str(self),
            "base_revision": self.base_revision,
            "current_revision": self.current_revision,
            "base_snapshot": self.base_snapshot,
            "current_snapshot": self.current_snapshot,
        }


class PreflightFailed(CeremonyError):
    """The pre-launch checklist scan found blocking problems.

    The recovery blueprint is NOT produced and no isolated resource is
    created; `problems` lists every failed checklist item.
    """

    code = "PREFLIGHT_FAILED"
    http_status = 422

    def __init__(self, problems: list[str] | str | None = None,
                 code: str | None = None):
        if isinstance(problems, str):
            problems = [problems]
        self.problems = problems or []
        super().__init__("; ".join(self.problems) or self.__class__.__doc__,
                         code)


class BlueprintStale(CeremonyError):
    """The source snapshot, target config or blueprint changed after scanning."""

    code = "BLUEPRINT_STALE"
    http_status = 409


class DrillFrozen(CeremonyError):
    """Mirroring was auto-frozen on a threshold breach; resume or terminate."""

    code = "DRILL_FROZEN"
    http_status = 409


class LeaseContention(CeremonyError):
    """Another control instance already holds the failover lease."""

    code = "LEASE_CONTENTION"
    http_status = 409


class CleanupBlocked(CeremonyError):
    """Critical resources cannot be deleted yet; `blockers` says why."""

    code = "CLEANUP_BLOCKED"
    http_status = 409

    def __init__(self, blockers: list[str] | str | None = None,
                 code: str | None = None):
        if isinstance(blockers, str):
            blockers = [blockers]
        self.blockers = blockers or []
        super().__init__("; ".join(self.blockers) or self.__class__.__doc__,
                         code)


class EvidenceError(CeremonyError):
    """The drill evidence archive failed verification."""

    code = "EVIDENCE_INVALID"
    http_status = 409

    def __init__(self, problems: list[str] | str | None = None,
                 code: str | None = None):
        if isinstance(problems, str):
            problems = [problems]
        self.problems = problems or []
        super().__init__("; ".join(self.problems) or self.__class__.__doc__,
                         code)
