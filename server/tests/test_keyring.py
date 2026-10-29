import pytest

from rekey.crypto import InvalidShares, Keyring, SealedError, envelope, initialize
from rekey.crypto.errors import DecryptionError


def unsealed(threshold: int = 3, shares: int = 5) -> tuple[Keyring, list[bytes]]:
    parts, config = initialize(threshold, shares)
    ring = Keyring(config)
    for p in parts[:threshold]:
        ring.unseal(p)
    assert not ring.sealed
    return ring, parts


def args(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "env_id": "env-prod",
        "env_key_version": 1,
        "path": "/",
        "name": "DATABASE_URL",
        "version": 1,
    }
    base.update(over)
    return base


def test_starts_sealed_and_unseals_at_threshold() -> None:
    parts, config = initialize(3, 5)
    ring = Keyring(config)
    assert ring.sealed
    assert ring.unseal(parts[0]) is False
    assert ring.unseal(parts[3]) is False
    assert ring.progress == (2, 3)
    assert ring.unseal(parts[4]) is True
    assert not ring.sealed


def test_wrong_shares_are_rejected_on_arrival_and_never_disturb_progress() -> None:
    real, config = initialize(2, 3)
    other, _ = initialize(2, 3)
    ring = Keyring(config)
    ring.unseal(real[0])
    with pytest.raises(InvalidShares):
        ring.unseal(other[0])  # another system's share
    with pytest.raises(InvalidShares):
        ring.unseal(bytes([1]) + b"\x00" * 32)  # right index, wrong bytes
    with pytest.raises(InvalidShares):
        ring.unseal(bytes([200]) + b"\x00" * 32)  # index that was never issued
    assert ring.progress == (1, 2) and ring.sealed
    assert ring.unseal(real[1]) is True  # the legitimate share still completes the unseal


def test_wrong_shares_are_still_detected_without_recorded_digests() -> None:
    """Seal records from before share digests existed fall back to the check at the threshold."""
    from dataclasses import replace

    _, config = initialize(2, 3)
    other, _ = initialize(2, 3)
    ring = Keyring(replace(config, share_hashes=b""))
    ring.unseal(other[0])
    with pytest.raises(InvalidShares):
        ring.unseal(other[1])
    assert ring.sealed


def test_sealed_keyring_refuses_work() -> None:
    parts, config = initialize(2, 3)
    ring = Keyring(config)
    with pytest.raises(SealedError):
        ring.new_env_key("env", 1)
    for p in parts[:2]:
        ring.unseal(p)
    wrapped = ring.new_env_key("env", 1)
    ring.seal()
    assert ring.sealed
    with pytest.raises(SealedError):
        ring.encrypt_value(wrapped, value=b"x", **args(env_id="env"))  # type: ignore[arg-type]


def test_encrypt_decrypt_roundtrip() -> None:
    ring, _ = unsealed()
    wrapped = ring.new_env_key("env-prod", 1)
    blob = ring.encrypt_value(wrapped, value=b"postgres://secret", **args())  # type: ignore[arg-type]
    assert b"postgres" not in blob
    assert ring.decrypt_value(wrapped, blob=blob, **args()) == b"postgres://secret"  # type: ignore[arg-type]


def test_nonces_are_unique() -> None:
    ring, _ = unsealed()
    wrapped = ring.new_env_key("env-prod", 1)
    a = ring.encrypt_value(wrapped, value=b"same", **args())  # type: ignore[arg-type]
    b = ring.encrypt_value(wrapped, value=b"same", **args())  # type: ignore[arg-type]
    assert a != b


@pytest.mark.parametrize(
    "change",
    [
        {"name": "OTHER"},
        {"path": "/other"},
        {"version": 2},
        {"env_id": "env-staging"},
    ],
)
def test_ciphertext_is_bound_to_its_context(change: dict[str, object]) -> None:
    ring, _ = unsealed()
    wrapped = ring.new_env_key("env-prod", 1)
    blob = ring.encrypt_value(wrapped, value=b"v", **args())  # type: ignore[arg-type]
    with pytest.raises(DecryptionError):
        ring.decrypt_value(wrapped, blob=blob, **args(**change))  # type: ignore[arg-type]


def test_tampered_ciphertext_is_rejected() -> None:
    ring, _ = unsealed()
    wrapped = ring.new_env_key("env-prod", 1)
    blob = bytearray(ring.encrypt_value(wrapped, value=b"v", **args()))  # type: ignore[arg-type]
    blob[-1] ^= 1
    with pytest.raises(DecryptionError):
        ring.decrypt_value(wrapped, blob=bytes(blob), **args())  # type: ignore[arg-type]


def test_environments_are_cryptographically_separate() -> None:
    ring, _ = unsealed()
    dev = ring.new_env_key("env-dev", 1)
    prod = ring.new_env_key("env-prod", 1)
    blob = ring.encrypt_value(prod, value=b"v", **args())  # type: ignore[arg-type]
    # Even with the same context, another environment's key cannot open it.
    with pytest.raises(DecryptionError):
        ring.decrypt_value(dev, blob=blob, **args(env_id="env-dev"))  # type: ignore[arg-type]


def test_wrapped_key_bound_to_environment() -> None:
    ring, _ = unsealed()
    wrapped = ring.new_env_key("env-prod", 1)
    with pytest.raises(DecryptionError):
        ring.encrypt_value(wrapped, value=b"v", **args(env_id="env-dev"))  # type: ignore[arg-type]


def test_root_rotation_rewraps_without_reencrypting() -> None:
    old, _ = unsealed()
    new, _ = unsealed()
    wrapped = old.new_env_key("env-prod", 1)
    blob = old.encrypt_value(wrapped, value=b"v", **args())  # type: ignore[arg-type]
    moved = old.rewrap(wrapped, "env-prod", 1, new)
    assert new.decrypt_value(moved, blob=blob, **args()) == b"v"  # type: ignore[arg-type]


def test_envelope_rejects_malformed_blobs() -> None:
    key = b"\x00" * 32
    with pytest.raises(DecryptionError):
        envelope.open_(key, b"short", b"")
    blob = envelope.seal(key, b"x", b"")
    with pytest.raises(DecryptionError):
        envelope.open_(key, b"\x02" + blob[1:], b"")  # unknown version
    with pytest.raises(ValueError):
        envelope.seal(b"short", b"x", b"")


def test_context_encoding_is_unambiguous() -> None:
    assert envelope.encode_context("ab", "c") != envelope.encode_context("a", "bc")
