"""Devices, device wallets and remote attestation.

Every rostered participant acts through a *device* (HSM, hardened laptop,
secure enclave). A device has three keys:

  * identity key  (Ed25519) - signs all ceremony action envelopes
  * sealing key   (MODP KEM) - receives Shamir shares encrypted to it
  * measurement   (SHA256)   - expected software/firmware measurement

Attestation = the device signs, with its identity key, a quote over
(challenge nonce, live measurement, device id, sealing pubkey, timestamp).
The orchestrator binds the presented sealing key to the enrolled key and
binds the live measurement to the expected one, and only then will seal a
share to the device. This models hardware-attestation (e.g. TPM Quote /
HSM attestation) without requiring the actual hardware here.
"""

from __future__ import annotations

import json
import os
import time

from . import crypto, ed25519
from .errors import AttestationError, AuthenticationError, ReplayError

EXPECTED_MEASUREMENT = None  # marker: device's own enrolled measurement


def gen_device_id() -> str:
    return "dev_" + os.urandom(8).hex()


def gen_participant_id() -> str:
    return "ppl_" + os.urandom(8).hex()


def measure_software(build: str = "kc-enclave-v1.0.0") -> bytes:
    """Deterministic 'firmware measurement' of the enclave software bundle."""
    return hashlib_sha256(build.encode())


def hashlib_sha256(b: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(b).digest()


class DeviceWallet:
    """A device-side key wallet. In production this lives inside the HSM;
    here it is a JSON file with 0600 permissions."""

    def __init__(self, device_id: str, identity_seed: bytes, seal_priv: int,
                 measurement: bytes, label: str = "", inbox: dict | None = None):
        self.device_id = device_id
        self.identity_seed = identity_seed
        self.seal_priv = seal_priv
        self.measurement = measurement
        self.label = label
        # Inbox: delivery_id -> sealed envelope JSON, cleared after submit.
        self.inbox = inbox or {}

    # ---- keys -----------------------------------------------------------
    @property
    def identity_pub(self) -> bytes:
        return ed25519.public_from_secret(self.identity_seed)

    @property
    def seal_pub(self) -> int:
        return pow(crypto.G2, self.seal_priv, crypto.q)

    # ---- persistence ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "identity_seed": crypto.b64e(self.identity_seed),
            "seal_priv": str(self.seal_priv),
            "measurement": crypto.b64e(self.measurement),
            "label": self.label,
            "inbox": self.inbox,
        }

    @staticmethod
    def from_dict(d: dict) -> "DeviceWallet":
        return DeviceWallet(
            d["device_id"], crypto.b64d(d["identity_seed"]), int(d["seal_priv"]),
            crypto.b64d(d["measurement"]), d.get("label", ""), d.get("inbox", {}))

    def save(self, path: str):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(self.to_dict(), f, indent=2)
        os.replace(tmp, path)

    @staticmethod
    def load(path: str) -> "DeviceWallet":
        with open(path, encoding="utf-8") as f:
            return DeviceWallet.from_dict(json.load(f))

    # ---- actions --------------------------------------------------------
    def quote(self, challenge: bytes, live_measurement: bytes | None = None,
              now: float | None = None) -> dict:
        live = self.measurement if live_measurement is None else live_measurement
        ts = int(time.time() if now is None else now)
        msg = self._quote_msg(challenge, live, self.seal_pub, ts)
        return {
            "device_id": self.device_id,
            "measurement": crypto.b64e(live),
            "seal_pub": str(self.seal_pub),
            "ts": ts,
            "sig": crypto.b64e(ed25519.sign(self.identity_seed, msg)),
        }

    def _quote_msg(self, challenge: bytes, measurement: bytes,
                   seal_pub: int, ts: int) -> bytes:
        return crypto.dumps({
            "t": "attestation-quote-v1",
            "device_id": self.device_id,
            "challenge": crypto.b64e(challenge),
            "measurement": crypto.b64e(measurement),
            "seal_pub": str(seal_pub),
            "ts": ts,
        }).encode()

    def sign_action(self, ceremony_id: str, stage: str, action: str,
                    payload: dict, nonce: str) -> dict:
        """Produce a signed action envelope (replay-protected by nonce)."""
        body = {
            "ceremony_id": ceremony_id,
            "stage": stage,
            "action": action,
            "payload": payload,
            "nonce": nonce,
        }
        msg = self._action_msg(body)
        return {
            "device_id": self.device_id,
            "body": body,
            "sig": crypto.b64e(ed25519.sign(self.identity_seed, msg)),
        }

    @staticmethod
    def _action_msg(body: dict) -> bytes:
        return crypto.dumps({"t": "kc-action-v1", "body": body}).encode()

    def open_delivery(self, delivery_id: str, expected_context: bytes) -> int:
        """Decrypt a sealed share delivered to this device. Returns share int."""
        env_json = self.inbox.get(delivery_id)
        if env_json is None:
            raise KeyError(delivery_id)
        env = crypto.envelope_from_json(env_json)
        if bytes(env["context"]) != expected_context:
            raise AttestationError("delivery context mismatch")
        data = crypto.open_seal(self.seal_priv, env)
        return crypto.bytes_to_int(data)

    def clear_delivery(self, delivery_id: str):
        self.inbox.pop(delivery_id, None)


def verify_action_envelope(envelope: dict, enrolled_pub: bytes) -> dict:
    """Verify device signature on an action envelope; returns its body."""
    body = envelope.get("body", {})
    sig = crypto.b64d(envelope.get("sig", ""))
    if not ed25519.verify(enrolled_pub, DeviceWallet._action_msg(body), sig):
        raise AuthenticationError("action envelope signature invalid")
    return body


def verify_quote(quote: dict, enrolled: "EnrolledDevice", challenge: bytes,
                 now: float, max_skew_seconds: int = 300) -> int:
    """Validate an attestation quote. Returns the attested seal_pub."""
    if quote.get("device_id") != enrolled.device_id:
        raise AttestationError("device_id mismatch")
    try:
        sig = crypto.b64d(quote["sig"])
        measurement = crypto.b64d(quote["measurement"])
        seal_pub = int(quote["seal_pub"])
        ts = int(quote["ts"])
    except (KeyError, ValueError) as e:
        raise AttestationError(f"malformed quote: {e}")
    # Reconstruct exact message that was signed.
    msg = crypto.dumps({
        "t": "attestation-quote-v1",
        "device_id": enrolled.device_id,
        "challenge": crypto.b64e(challenge),
        "measurement": crypto.b64e(measurement),
        "seal_pub": str(seal_pub),
        "ts": ts,
    }).encode()
    if not ed25519.verify(enrolled.identity_pub, msg, sig):
        raise AttestationError("quote signature invalid")
    if not hmac_eq(measurement, enrolled.measurement):
        raise AttestationError("measurement mismatch: untrusted software state")
    if abs(now - ts) > max_skew_seconds:
        raise AttestationError("quote outside acceptable time window")
    if seal_pub != enrolled.seal_pub:
        raise AttestationError("sealing public key does not match enrolled key")
    # Point must lie in the prime-order subgroup.
    if pow(seal_pub, crypto.QP, crypto.q) != 1 or seal_pub in (0, 1):
        raise AttestationError("seal key not in prime-order subgroup")
    return seal_pub


def hmac_eq(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)


class EnrolledDevice:
    """Server-side record of an enrolled device (public material only)."""

    def __init__(self, device_id: str, participant_id: str, label: str,
                 identity_pub: bytes, seal_pub: int, measurement: bytes,
                 enrolled_at: float, revoked: bool = False):
        self.device_id = device_id
        self.participant_id = participant_id
        self.label = label
        self.identity_pub = identity_pub
        self.seal_pub = seal_pub
        self.measurement = measurement
        self.enrolled_at = enrolled_at
        self.revoked = revoked

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "participant_id": self.participant_id,
            "label": self.label,
            "identity_pub": crypto.b64e(self.identity_pub),
            "seal_pub": str(self.seal_pub),
            "measurement": crypto.b64e(self.measurement),
            "enrolled_at": self.enrolled_at,
            "revoked": self.revoked,
        }

    @staticmethod
    def from_dict(d: dict) -> "EnrolledDevice":
        return EnrolledDevice(
            d["device_id"], d["participant_id"], d.get("label", ""),
            crypto.b64d(d["identity_pub"]), int(d["seal_pub"]),
            crypto.b64d(d["measurement"]), d["enrolled_at"],
            d.get("revoked", False))


def provision_device(device_id: str, label: str,
                     measurement: bytes | None = None) -> DeviceWallet:
    """Factory for a fresh device wallet (simulates HSM initialization)."""
    seed = os.urandom(32)
    seal_priv, _ = crypto.gen_seal_keypair()
    meas = measure_software() if measurement is None else measurement
    return DeviceWallet(device_id, seed, seal_priv, meas, label)
