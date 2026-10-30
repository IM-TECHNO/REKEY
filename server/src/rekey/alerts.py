"""Mail an administrator when something needs a person: a rotation or a dynamic account failed, a
change is waiting for approval, the server is sealed, or the audit log no longer checks out.

Where the mail goes (SMTP host, sender, recipients, which events) is set by a superadmin in the UI
and kept in the database. The SMTP password is the one thing that is not: it comes from
REKEY_SMTP_PASSWORD, so it is not in backups, survives a root-key rotation and works while sealed.

Events come from two places. Most are audit events (`audit.listen`): the code that already records
"rotation.fail" or "change.create" needs no changes. A small background task adds what no request
triggers: still sealed after a restart, and the periodic audit-chain and anchor check.

Mail never carries secret values, only names and the already-cleaned error text. The same ongoing
problem is mailed at most once per `alert_repeat_hours`, and there is a global cap per hour so a
flood of requests cannot turn Rekey into a mail cannon.
"""

import asyncio
import contextlib
import logging
import re
import smtplib
import ssl
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from rekey import anchor, audit
from rekey.api import DB, Admin, log
from rekey.config import Settings
from rekey.models import AlertConfig, SealRow

logger = logging.getLogger("rekey.alerts")

ACTOR = "alerts"
_TIMEOUT = 15.0
_MAX_PER_HOUR = 30
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_ADDRESS = re.compile(r"^[^\s@<>,;\"'()\[\]\\]{1,64}@[^\s@<>,;\"'()\[\]\\]{1,253}$")
_LOOPBACK = ("localhost", "127.0.0.1", "::1")

EVENTS: dict[str, str] = {
    "rotation_failed": "A scheduled rotation failed",
    "dynamic_failed": "A dynamic account could not be created or removed",
    "approval_pending": "A change or a renewal is waiting for approval",
    "sealed": "The server is sealed",
    "integrity": "The audit log or its anchors no longer check out",
}
# audit action -> event
_FROM_AUDIT = {
    "rotation.fail": "rotation_failed",
    "dynamic.fail": "dynamic_failed",
    "change.create": "approval_pending",
    "dynamic.renew-request": "approval_pending",
    "sys.seal": "sealed",
}
_SUBJECT = {
    "rotation_failed": "rotation failed",
    "dynamic_failed": "dynamic account problem",
    "approval_pending": "approval needed",
    "sealed": "server is sealed",
    "integrity": "audit log check failed",
}


# ---- sending ------------------------------------------------------------------------------


def _one_line(text: str, limit: int = 300) -> str:
    return " ".join(text.split())[:limit]


def _body(event: str, facts: dict[str, str]) -> str:
    lines = [EVENTS.get(event, "Test") + ".", ""]
    for label, name in (("Where", "where"), ("What", "what"), ("By", "actor")):
        if facts.get(name):
            lines.append(f"{label}: {facts[name]}")
    lines += ["", "Open Rekey to look into it. Alerts never contain secret values."]
    return "\n".join(lines)


def _send_sync(
    host: str,
    port: int,
    security: str,
    user: str,
    password: str,
    sender: str,
    to: list[str],
    subject: str,
    body: str,
) -> None:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Subject"] = _one_line(subject, 200)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2] or "rekey.invalid")
    msg.set_content(body)
    context = ssl.create_default_context()  # verifies the certificate and the host name
    if security == "ssl":
        client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=_TIMEOUT, context=context)
    else:
        client = smtplib.SMTP(host, port, timeout=_TIMEOUT)
    with client:
        client.ehlo()
        if security == "starttls":
            client.starttls(context=context)
            client.ehlo()
        if user:
            client.login(user, password)
        client.send_message(msg)


Sender = Callable[..., None]


class Mailer:
    """Everything needed to send one mail; built from the stored settings and the password."""

    def __init__(self, cfg: AlertConfig, password: str, sender: Sender = _send_sync) -> None:
        self.cfg, self.password, self._sender = cfg, password, sender

    @property
    def recipients(self) -> list[str]:
        return [r for r in self.cfg.recipients.split(",") if r]

    @property
    def ready(self) -> bool:
        return bool(self.cfg.smtp_host and self.cfg.mail_from and self.recipients)

    async def send(self, subject: str, body: str) -> None:
        await asyncio.to_thread(
            self._sender,
            self.cfg.smtp_host,
            self.cfg.smtp_port,
            self.cfg.smtp_security,
            self.cfg.smtp_user,
            self.password,
            self.cfg.mail_from,
            self.recipients,
            subject,
            body,
        )

    def clean_error(self, exc: Exception) -> str:
        text = _one_line(f"{exc.__class__.__name__}: {exc}")
        if self.password:
            text = text.replace(self.password, "***")
        return text


# ---- the notifier -------------------------------------------------------------------------


class Notifier:
    """Decides whether an event is mailed, and mails it. Never raises into its caller."""

    def __init__(
        self,
        settings: Settings,
        sessionmaker: async_sessionmaker[AsyncSession],
        sender: Sender = _send_sync,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.sessionmaker = sessionmaker
        self.sender = sender
        self.http = http or httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False)
        self.last_sent_at: datetime | None = None
        self.last_error: str = ""
        self._recent: dict[str, float] = {}
        self._hour: deque[float] = deque()
        self._tasks: set[asyncio.Task[None]] = set()
        self._sealed_since: float | None = None

    async def config(self) -> AlertConfig | None:
        async with self.sessionmaker() as db:
            return await db.get(AlertConfig, 1)

    async def mailer(self) -> Mailer | None:
        cfg = await self.config()
        if cfg is None:
            return None
        return Mailer(cfg, self.settings.smtp_password, self.sender)

    # audit.listen callback: synchronous and fast, the work happens in a task.
    def on_audit(
        self, actor: str, action: str, outcome: str, project: str, environment: str, target: str
    ) -> None:
        event = _FROM_AUDIT.get(action)
        if event is None or outcome != "allow":
            return
        where = f"{project}/{environment}".strip("/")
        word = target.split(" ", 1)[0] if target else ""
        # Approvals are one-off facts; failures repeat, so they are de-duplicated per target.
        key = {"approval_pending": None, "sealed": "sealed"}.get(event, f"{action}:{where}:{word}")
        task = asyncio.get_running_loop().create_task(
            self.notify(
                event,
                key,
                {"actor": actor, "where": where, "what": _one_line(target, 500), "action": action},
            )
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _allowed_now(self, key: str | None) -> bool:
        now = time.monotonic()
        while self._hour and now - self._hour[0] > 3600:
            self._hour.popleft()
        if key is not None:
            seen = self._recent.get(key)
            if seen is not None and now - seen < self.settings.alert_repeat_hours * 3600:
                return False
        if len(self._hour) >= _MAX_PER_HOUR:
            logger.warning("alert mail capped at %s per hour; one was dropped", _MAX_PER_HOUR)
            return False
        if key is not None:
            if len(self._recent) > 1000:
                self._recent = {k: t for k, t in self._recent.items() if now - t < 86400}
            self._recent[key] = now
        self._hour.append(now)
        return True

    def forget(self, key: str) -> None:
        """The problem is over: the next occurrence is mailed at once."""
        self._recent.pop(key, None)

    def hook_ready(self, cfg: AlertConfig) -> bool:
        return cfg.webhook_kind != "off" and bool(self.settings.alert_webhook_url)

    async def post_hook(
        self, cfg: AlertConfig, event: str, subject: str, facts: dict[str, str]
    ) -> None:
        """POST to the chat webhook. Raises with a message that cannot contain the URL."""
        text = _body(event, facts)
        if cfg.webhook_kind == "slack":
            # Slack (and Mattermost, Rocket.Chat): escape so a name cannot ping @channel.
            esc = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            payload: dict[str, Any] = {"text": f"*{subject}*\n{esc}"}
        elif cfg.webhook_kind == "discord":
            payload = {
                "content": f"**{subject}**\n{text}"[:1900],
                "allowed_mentions": {"parse": []},
            }
        else:
            payload = {
                "event": event,
                "subject": subject,
                "where": facts.get("where", ""),
                "what": facts.get("what", ""),
                "actor": facts.get("actor", ""),
                "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        try:
            resp = await self.http.post(self.settings.alert_webhook_url, json=payload)
        except Exception as exc:  # noqa: BLE001 - httpx messages can carry the URL
            raise RuntimeError(f"webhook failed ({exc.__class__.__name__})") from None
        if resp.status_code >= 300:
            raise RuntimeError(f"webhook answered {resp.status_code}")

    async def notify(self, event: str, key: str | None, facts: dict[str, str]) -> None:
        try:
            cfg = await self.config()
            if cfg is None or event not in cfg.events.split(","):
                return
            mailer = Mailer(cfg, self.settings.smtp_password, self.sender)
            email_on = cfg.enabled and mailer.ready
            hook_on = self.hook_ready(cfg)
            if not (email_on or hook_on) or not self._allowed_now(key):
                return
            subject = f"[Rekey] {_SUBJECT[event]}"
            if facts.get("where"):
                subject += f" ({facts['where']})"
            errors: list[str] = []
            delivered = False
            if email_on:
                try:
                    await mailer.send(subject, _body(event, facts))
                    delivered = True
                except Exception as exc:  # noqa: BLE001 - a broken mail server must not break Rekey
                    errors.append(f"email: {mailer.clean_error(exc)}")
            if hook_on:
                try:
                    await self.post_hook(cfg, event, subject, facts)
                    delivered = True
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"chat: {_one_line(str(exc))}")
            self.last_error = "; ".join(errors)
            if errors:
                logger.warning("alert delivery failed: %s", self.last_error)
            if delivered:
                self.last_sent_at = datetime.now(UTC)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("alert handling failed")

    # ---- background checks ----------------------------------------------------------------

    async def check_sealed(self, ring: Any) -> None:
        async with self.sessionmaker() as db:
            initialised = (await db.execute(select(SealRow.id))).first() is not None
        sealed = initialised and (ring is None or ring.sealed)
        if not sealed:
            self._sealed_since = None
            self.forget("sealed")
            return
        now = time.monotonic()
        if self._sealed_since is None:
            self._sealed_since = now
        if now - self._sealed_since >= self.settings.alert_sealed_after_minutes * 60:
            await self.notify(
                "sealed",
                "sealed",
                {"what": "sealed and not unsealed again since the server started or sealed"},
            )

    async def integrity_problems(self) -> list[str]:
        problems: list[str] = []
        async with self.sessionmaker() as db:
            result = await audit.verify(db)
            if not result.ok:
                problems.append(f"the audit chain is broken at event {result.first_bad_seq}")
            if self.settings.audit_anchor_file:
                check = await anchor.check_anchors(db, self.settings.audit_anchor_file)
                if check.mismatched:
                    shown = ", ".join(str(s) for s in check.mismatched[:5])
                    problems.append(
                        f"{len(check.mismatched)} anchored head(s) differ from the database "
                        f"(event {shown}): history was changed"
                    )
        return problems

    async def check_integrity(self) -> None:
        problems = await self.integrity_problems()
        if not problems:
            self.forget("integrity")
            return
        await self.notify("integrity", "integrity", {"what": "; ".join(problems)})


async def run_forever(
    app: Any, *, poll_seconds: float = 30.0, stop: asyncio.Event | None = None
) -> None:
    notifier: Notifier = app.state.alerts
    stop = stop or asyncio.Event()
    next_integrity = 0.0
    while not stop.is_set():
        try:
            await notifier.check_sealed(app.state.keyring)
            if time.monotonic() >= next_integrity:
                next_integrity = (
                    time.monotonic() + max(1, notifier.settings.alert_check_minutes) * 60
                )
                await notifier.check_integrity()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad round must not stop the checks
            logger.exception("alert checks failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), poll_seconds)


# ---- API (superadmin only) ----------------------------------------------------------------

router = APIRouter(prefix="/v1/sys/alerts")


class AlertIn(BaseModel):
    enabled: bool = False
    smtp_host: str = Field("", max_length=253)
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_security: Literal["starttls", "ssl", "none"] = "starttls"
    smtp_user: str = Field("", max_length=200)
    mail_from: str = Field("", max_length=254)
    recipients: list[str] = Field(default_factory=list, max_length=10)
    events: list[str] = Field(default_factory=list)
    webhook_kind: Literal["off", "slack", "discord", "generic"] = "off"


def _out(cfg: AlertConfig | None, notifier: Notifier) -> dict[str, Any]:
    cfg = cfg or AlertConfig(
        enabled=False,
        smtp_host="",
        smtp_port=587,
        smtp_security="starttls",
        smtp_user="",
        mail_from="",
        recipients="",
        events=",".join(EVENTS),
        webhook_kind="off",
        updated_by="",
        updated_at=datetime.now(UTC),
    )
    return {
        "enabled": cfg.enabled,
        "smtp_host": cfg.smtp_host,
        "smtp_port": cfg.smtp_port,
        "smtp_security": cfg.smtp_security,
        "smtp_user": cfg.smtp_user,
        "mail_from": cfg.mail_from,
        "recipients": [r for r in cfg.recipients.split(",") if r],
        "events": [e for e in cfg.events.split(",") if e],
        "available_events": EVENTS,
        "password_set": bool(notifier.settings.smtp_password),
        "webhook_kind": cfg.webhook_kind,
        "webhook_url_set": bool(notifier.settings.alert_webhook_url),
        "last_sent_at": notifier.last_sent_at.isoformat() if notifier.last_sent_at else None,
        "last_error": notifier.last_error,
        "updated_by": cfg.updated_by,
    }


def _validate(body: AlertIn, password: str, hook_url: str = "") -> AlertIn:
    if body.webhook_kind != "off":
        if not hook_url:
            raise HTTPException(
                422, "chat alerts need REKEY_ALERT_WEBHOOK_URL in .env (then restart)"
            )
        try:
            anchor.check_webhook_url(hook_url, "REKEY_ALERT_WEBHOOK_URL")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
    host = body.smtp_host.strip()
    sender = body.mail_from.strip()
    recipients = list(dict.fromkeys(r.strip().lower() for r in body.recipients if r.strip()))
    if host and not _HOST.match(host):
        raise HTTPException(422, "smtp_host is not a valid host name")
    for addr in [sender, *recipients] if sender else recipients:
        if not _ADDRESS.match(addr):
            raise HTTPException(422, f"not a valid email address: {addr[:80]}")
    unknown = [e for e in body.events if e not in EVENTS]
    if unknown:
        raise HTTPException(422, f"unknown event: {unknown[0][:40]}")
    if body.smtp_security == "none" and body.smtp_user and host not in _LOOPBACK:
        raise HTTPException(
            422, "a login would be sent unencrypted; use starttls or ssl, or no login on this relay"
        )
    if body.enabled:
        if not (host and sender and recipients):
            raise HTTPException(
                422, "to turn alerts on, set the SMTP host, a sender and a recipient"
            )
        if body.smtp_user and not password:
            raise HTTPException(
                422,
                "a login name is set but REKEY_SMTP_PASSWORD is empty; set it in .env and restart",
            )
    return body.model_copy(
        update={"smtp_host": host, "mail_from": sender, "recipients": recipients}
    )


@router.get("")
async def get_alerts(request: Request, db: DB, who: Admin) -> dict[str, Any]:
    notifier: Notifier = request.app.state.alerts
    return _out(await db.get(AlertConfig, 1), notifier)


@router.put("")
async def put_alerts(request: Request, db: DB, who: Admin, body: AlertIn) -> dict[str, Any]:
    notifier: Notifier = request.app.state.alerts
    s = request.app.state.settings
    body = _validate(body, s.smtp_password, s.alert_webhook_url)
    cfg = await db.get(AlertConfig, 1)
    if cfg is None:
        cfg = AlertConfig(id=1)
        db.add(cfg)
    cfg.enabled = body.enabled
    cfg.smtp_host = body.smtp_host
    cfg.smtp_port = body.smtp_port
    cfg.smtp_security = body.smtp_security
    cfg.smtp_user = body.smtp_user.strip()
    cfg.mail_from = body.mail_from
    cfg.recipients = ",".join(body.recipients)
    cfg.events = ",".join(e for e in EVENTS if e in body.events)
    cfg.webhook_kind = body.webhook_kind
    cfg.updated_by = who.name
    cfg.updated_at = datetime.now(UTC)
    await db.commit()
    await log(
        request,
        who.name,
        "alerts.update",
        target=f"email {'on' if body.enabled else 'off'}, chat {body.webhook_kind}",
    )
    return _out(cfg, notifier)


@router.post("/test")
async def send_test(request: Request, db: DB, who: Admin) -> dict[str, Any]:
    """Send a test through every configured channel and report the real outcome of each."""
    notifier: Notifier = request.app.state.alerts
    cfg = await notifier.config()
    mailer = Mailer(cfg, request.app.state.settings.smtp_password, notifier.sender) if cfg else None
    email_on = mailer is not None and mailer.ready
    hook_on = cfg is not None and notifier.hook_ready(cfg)
    if not (email_on or hook_on):
        raise HTTPException(
            409, "save an SMTP host, a sender and a recipient, or a chat format, first"
        )
    errors: list[str] = []
    if email_on and mailer is not None:
        try:
            await mailer.send(
                "[Rekey] test mail",
                f"This is a test from Rekey, sent by {who.name}.\n"
                "If you can read it, alerts can reach you.",
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"email: {mailer.clean_error(exc)}")
    if hook_on and cfg is not None:
        try:
            await notifier.post_hook(
                cfg,
                "test",
                "[Rekey] test message",
                {"what": f"A test sent by {who.name}. If you can read it, alerts can reach you."},
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"chat: {_one_line(str(exc))}")
    if errors:
        message = "; ".join(errors)
        await log(request, who.name, "alerts.test", "deny", target=message[:200])
        return {"ok": False, "error": message}
    await log(request, who.name, "alerts.test", target="ok")
    return {"ok": True, "error": ""}
