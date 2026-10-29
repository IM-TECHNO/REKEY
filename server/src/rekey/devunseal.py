"""Development-only auto-unseal from a file of shares.

Sealing exists so that a copy of the database or the disk is useless without the shares. Keeping the
shares in a file next to the server removes that protection completely, so this is for local
development and demos only: it refuses to start when cookies are marked Secure (a real HTTPS
deployment), logs a warning on every start, and the UI shows a banner while it is on.
"""

import base64
import binascii
import logging
from typing import Any

from sqlalchemy import select

from rekey import audit
from rekey.crypto import InvalidShares, Keyring, SealConfig
from rekey.models import SealRow

logger = logging.getLogger("rekey.devunseal")
ACTOR = "dev-auto-unseal"


def check_allowed(settings: Any) -> None:
    if settings.dev_unseal_file and settings.cookie_secure:
        raise RuntimeError(
            "REKEY_DEV_UNSEAL_FILE keeps the unseal shares on disk and is for local development "
            "only; it refuses to run while REKEY_COOKIE_SECURE=true (a real deployment)"
        )


async def try_unseal(app: Any) -> bool:
    """Unseal from the configured file. Returns True when the server ends up unsealed."""
    settings = app.state.settings
    async with app.state.sessionmaker() as db:
        row = (await db.execute(select(SealRow))).scalar_one_or_none()
    if row is None:
        logger.warning("dev auto-unseal: not initialised yet; run /v1/sys/init, then restart")
        return False
    try:
        with open(settings.dev_unseal_file, encoding="utf-8") as fh:
            lines = [x.strip() for x in fh if x.strip() and not x.startswith("#")]
    except OSError as exc:
        logger.error("dev auto-unseal: cannot read the shares file (%s)", exc.__class__.__name__)
        return False
    ring = Keyring(SealConfig(row.threshold, row.shares, row.check_blob, row.share_hashes or b""))
    try:
        for line in lines:
            if not ring.sealed:
                break
            ring.unseal(base64.urlsafe_b64decode(line.encode()))
    except (binascii.Error, InvalidShares):
        logger.error("dev auto-unseal: the shares file holds an invalid share")
        return False
    if ring.sealed:
        logger.error("dev auto-unseal: the shares file does not hold enough shares")
        return False
    app.state.keyring = ring
    logger.warning(
        "DEV AUTO-UNSEAL IS ON: the unseal shares are read from a file, so sealing protects "
        "nothing. Never use this with real secrets."
    )
    await audit.record(app.state.sessionmaker, actor=ACTOR, action="sys.unseal")
    return True
