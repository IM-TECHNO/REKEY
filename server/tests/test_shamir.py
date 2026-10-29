import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rekey.crypto import InvalidShares, combine, split
from rekey.crypto import shamir as sh


def test_gf256_known_answers() -> None:
    # FIPS-197 section 4.2: {57} x {83} = {c1}
    assert sh._mul(0x57, 0x83) == 0xC1
    assert sh._mul(0x57, 0x13) == 0xFE
    # multiplicative inverse: a * a^-1 = 1 for every non-zero element
    for a in range(1, 256):
        assert sh._mul(a, sh._div(1, a)) == 1


def test_every_threshold_subset_recovers_secret() -> None:
    secret = bytes(range(32))
    parts = split(secret, 3, 5)
    for subset in itertools.combinations(parts, 3):
        assert combine(list(subset)) == secret
    assert combine(parts) == secret  # more than threshold also works


def test_below_threshold_does_not_recover() -> None:
    secret = bytes(range(32))
    parts = split(secret, 3, 5)
    for subset in itertools.combinations(parts, 2):
        assert combine(list(subset)) != secret


def test_shares_are_randomised() -> None:
    secret = b"\x01" * 32
    assert split(secret, 2, 3) != split(secret, 2, 3)


@settings(max_examples=60, deadline=None)
@given(
    secret=st.binary(min_size=1, max_size=48),
    data=st.data(),
)
def test_roundtrip_property(secret: bytes, data: st.DataObject) -> None:
    n = data.draw(st.integers(min_value=2, max_value=8))
    k = data.draw(st.integers(min_value=2, max_value=n))
    parts = split(secret, k, n)
    chosen = data.draw(st.permutations(parts).map(lambda p: p[:k]))
    assert combine(list(chosen)) == secret


def test_bad_parameters_rejected() -> None:
    with pytest.raises(ValueError):
        split(b"", 2, 3)
    with pytest.raises(ValueError):
        split(b"x", 1, 3)
    with pytest.raises(ValueError):
        split(b"x", 4, 3)
    with pytest.raises(ValueError):
        split(b"x", 2, 256)


def test_malformed_shares_rejected() -> None:
    parts = split(b"secret-secret-secret", 2, 3)
    with pytest.raises(InvalidShares):
        combine([parts[0]])
    with pytest.raises(InvalidShares):
        combine([parts[0], parts[0]])  # duplicate index
    with pytest.raises(InvalidShares):
        combine([parts[0], parts[1][:-1]])  # length mismatch
    with pytest.raises(InvalidShares):
        combine([bytes([0]) + parts[0][1:], parts[1]])  # index 0 is invalid
