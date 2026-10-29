class CryptoError(Exception):
    """Base class for all errors raised by the crypto core."""


class InvalidShares(CryptoError):
    """The supplied unseal shares are malformed or do not reconstruct the root key."""


class SealedError(CryptoError):
    """An operation needing the key encryption key was attempted while sealed."""


class DecryptionError(CryptoError):
    """Authentication failed: wrong key, wrong context, or tampered data."""
