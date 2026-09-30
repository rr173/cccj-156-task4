"""Fixed roles, ceremony types and immutable policy snapshots.

A policy defines *who* may hold shares (roster of participant/device slots),
*how many* are needed (threshold) and *which* roles must be present for a
quorum. Every ceremony captures a deep-frozen snapshot of the policy; changes
after a ceremony starts cannot affect the running round (they abort it, by
requirement), which is why policies are versioned and append-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import PolicyViolation

# Four fixed ceremony kinds for the root key lifecycle.
GENERATE = "GENERATE"
ROTATE = "ROTATE"
BACKUP = "BACKUP"        # recovery of lost shares / lost participants
DESTROY = "DESTROY"

CEREMONY_KINDS = (GENERATE, ROTATE, BACKUP, DESTROY)

# Fixed participation roles. No role alone holds enough material to rebuild.
ROOT_OWNER = "ROOT_OWNER"        # e.g. security officer: authorizes lifecycle
KEY_STEWARD = "KEY_STEWARD"      # datacenter HSM custodian
WITNESS_SHAREHOLDER = "WITNESS_SHAREHOLDER"  # independent witness quorum
ENCLAVE_OPERATOR = "ENCLAVE_OPERATOR"  # runs the sealed signing enclave

ROLES = (ROOT_OWNER, KEY_STEWARD, WITNESS_SHAREHOLDER, ENCLAVE_OPERATOR)
SHAREHOLDER_ROLES = (ROOT_OWNER, KEY_STEWARD, WITNESS_SHAREHOLDER)
REQUIRED_ROLES = (ROOT_OWNER, WITNESS_SHAREHOLDER)  # at least one of each

# Stages every ceremony passes through, in strict order.
STAGES = (
    "OPEN",            # snapshot locked, challenge/nonce issued
    "ATTESTED",        # device quote collected for rostered devices
    "DELIVERED",       # (generate/rotate) sealed shares on devices
    "CONFIRMED",       # shareholder confirmations (quorum)
    "COMMIT",          # materialize key/version or run recovery math
    "COMPLETED",
)
TERMINAL_STAGES = ("COMPLETED", "ABORTED")


@dataclass
class Slot:
    """A rostered shareholding slot: person/identity bound to one device."""

    participant_id: str
    role: str
    device_id: str

    def to_dict(self) -> dict:
        return {"participant_id": self.participant_id, "role": self.role,
                "device_id": self.device_id}

    @staticmethod
    def from_dict(d: dict) -> "Slot":
        return Slot(d["participant_id"], d["role"], d["device_id"])


@dataclass
class Policy:
    policy_id: str
    version: int
    label: str
    threshold: int
    handover_seconds: int          # old/new key coexistence window
    ceremony_timeout_seconds: int
    purposes: tuple[str, ...]      # e.g. ("root-signing", "sealing")
    slots: list[Slot] = field(default_factory=list)
    superseded_by: str | None = None

    def snapshot(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "label": self.label,
            "threshold": self.threshold,
            "handover_seconds": self.handover_seconds,
            "ceremony_timeout_seconds": self.ceremony_timeout_seconds,
            "purposes": list(self.purposes),
            "slots": [s.to_dict() for s in self.slots],
        }

    def to_dict(self) -> dict:
        d = self.snapshot()
        d["superseded_by"] = self.superseded_by
        return d

    @staticmethod
    def from_dict(d: dict) -> "Policy":
        return Policy(
            policy_id=d["policy_id"], version=d["version"], label=d["label"],
            threshold=d["threshold"], handover_seconds=d["handover_seconds"],
            ceremony_timeout_seconds=d["ceremony_timeout_seconds"],
            purposes=tuple(d["purposes"]),
            slots=[Slot.from_dict(s) for s in d["slots"]],
            superseded_by=d.get("superseded_by"),
        )

    def validate(self):
        n = len(self.slots)
        if n < 3:
            raise PolicyViolation("roster must have at least 3 fixed participants")
        if self.threshold < 2:
            raise PolicyViolation("threshold must be >= 2")
        if self.threshold > n:
            raise PolicyViolation("threshold cannot exceed roster size")
        ids = [s.participant_id for s in self.slots]
        if len(set(ids)) != len(ids):
            raise PolicyViolation("participant_id must be unique in roster")
        devs = [s.device_id for s in self.slots]
        if len(set(devs)) != len(devs):
            raise PolicyViolation("device_id must be unique in roster")
        roles = {s.role for s in self.slots}
        for r in REQUIRED_ROLES:
            if r not in roles:
                raise PolicyViolation(f"roster must contain role {r}")
        for s in self.slots:
            if s.role not in ROLES:
                raise PolicyViolation(f"unknown role {s.role}")
        # No single-role majority: one role alone must never reach threshold.
        from collections import Counter
        for role, count in Counter(s.role for s in self.slots).items():
            if count >= self.threshold and role not in (WITNESS_SHAREHOLDER,):
                # Witness role is designed to hold multiple *independent*
                # witnesses; that's the one allowed majority. Owners/stewards
                # (organization roles) cannot concentrate enough shares alone.
                raise PolicyViolation(
                    f"role {role} alone could meet threshold; split the role")
        if not self.purposes:
            raise PolicyViolation("policy must name at least one key purpose")

    def slots_for_role(self, role: str) -> list[Slot]:
        return [s for s in self.slots if s.role == role]

    def slot_for_device(self, device_id: str) -> Slot | None:
        for s in self.slots:
            if s.device_id == device_id:
                return s
        return None

    def slot_for_participant(self, participant_id: str) -> Slot | None:
        for s in self.slots:
            if s.participant_id == participant_id:
                return s
        return None

    def quorum_ok(self, present_devices: set[str], kind: str,
                  confirmed_devices: set[str] | None = None) -> None:
        """Raise PolicyViolation unless the present/confirmed set is a legal
        quorum for the ceremony kind. 'present' is the attested set;
        'confirmed' is the set of explicit shareholder confirmations."""
        present = set(present_devices)
        present_roles = {s.role for s in self.slots if s.device_id in present}
        for r in REQUIRED_ROLES:
            if r not in present_roles:
                raise PolicyViolation(f"quorum requires at least one {r}")
        if kind in (GENERATE, ROTATE, DESTROY):
            if len(present) < self.threshold:
                raise PolicyViolation(
                    f"{kind} requires all-roster attested sessions, "
                    f"{len(present)}/{self.threshold} present")
            if len(present) != len(self.slots):
                raise PolicyViolation(
                    f"{kind} requires the full fixed roster "
                    f"({len(present)}/{len(self.slots)} present); "
                    "missing participant -> abort this round, start a BACKUP")
        # Explicit confirmations must come from >= threshold shareholders of
        # distinct participants, always including at least one owner.
        conf = set(confirmed_devices or present)
        conf_slots = [s for s in self.slots if s.device_id in conf]
        if len({s.participant_id for s in conf_slots}) < self.threshold:
            raise PolicyViolation(
                f"need confirmations from >= {self.threshold} participants, "
                f"have {len({s.participant_id for s in conf_slots})}")
        if not any(s.role == ROOT_OWNER for s in conf_slots):
            raise PolicyViolation("a ROOT_OWNER must confirm")
