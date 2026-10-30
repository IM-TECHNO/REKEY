from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REKEY_")

    database_url: str = "postgresql+asyncpg://rekey:rekey@localhost:5432/rekey"
    # Break-glass superadmin credential. Unset = no bootstrap access.
    bootstrap_token: str = ""

    # GitLab (or any OIDC provider) login for people. Empty issuer = OIDC login disabled.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""  # https://<rekey host>/v1/auth/oidc/callback
    oidc_scopes: str = "openid profile email"
    # If set, only members of this GitLab group (full path) may log in.
    oidc_required_group: str = ""

    # GitLab CI ID tokens for pipelines. Jobs request a token with `aud: <ci_audience>`.
    ci_audience: str = "rekey"

    # GitLab numeric user ids (the OIDC `sub`) of people who are superadmins when they log in.
    # Ids, not usernames: a GitLab username can be renamed or re-registered, the id cannot.
    # Comma separated. CI sessions are never superadmin. `rekey whoami` / the UI shows your id.
    superadmin_subjects: str = ""

    # How many reverse proxies sit in front of the API and append to X-Forwarded-For (the Next.js
    # UI counts as one; add one per extra proxy such as nginx). 0 = trust no header, use the socket.
    trusted_proxy_hops: int = 0

    # Per client IP, per minute (0 disables a limit).
    rate_login_per_min: int = 20  # OIDC login redirect and callback
    rate_exchange_per_min: int = 10  # CLI one-time code exchange
    rate_ci_login_per_min: int = 60  # CI runners can share an address
    rate_unseal_per_min: int = 10
    # Failed authentications per client IP in five minutes before that IP is blocked for the rest
    # of the window.
    rate_auth_failures_per_5min: int = 20

    # Copy the audit chain's head hash somewhere an administrator of this database cannot rewrite
    # (see anchor.py). Either or both; both empty = off. The file holds one JSON line per anchor.
    audit_anchor_file: str = ""
    audit_anchor_webhook: str = ""  # https URL receiving a JSON POST {ts, seq, head}
    audit_anchor_token: str = ""  # optional Bearer token sent to the webhook
    audit_anchor_interval_seconds: int = 300

    # DEVELOPMENT ONLY: a file with one base64 unseal share per line; the server unseals itself at
    # start. It defeats the point of sealing, so it refuses to run with cookie_secure=true.
    dev_unseal_file: str = ""

    # Auto-unseal: keep the key-encryption key wrapped by an external key service so the server can
    # unseal itself at start (see autounseal.py and docs/AUTO-UNSEAL.md). off = unseal by shares.
    auto_unseal: Literal["off", "transit", "aws-kms"] = "off"
    auto_unseal_addr: str = ""  # transit: https://vault.example.com:8200
    auto_unseal_token: str = ""  # transit: a token that may only encrypt/decrypt with the key
    auto_unseal_token_file: str = ""  # transit: read the token from this file instead
    auto_unseal_key: str = ""  # transit: key name; aws-kms: key id, ARN or alias
    auto_unseal_mount: str = "transit"  # transit: where the engine is mounted
    auto_unseal_namespace: str = ""  # transit: Vault Enterprise / OpenBao namespace
    auto_unseal_region: str = ""  # aws-kms: region (empty = the usual AWS environment)

    # Alert mail (alerts.py). Host, sender and recipients are set in the UI; only the SMTP password
    # lives here, so it is not in the database and works while the server is sealed.
    smtp_password: str = ""
    alert_check_minutes: int = 60  # how often the audit chain and anchors are re-checked
    alert_sealed_after_minutes: int = 5  # sealed this long (e.g. after a restart) raises an alert
    alert_repeat_hours: int = 6  # the same ongoing problem is mailed at most this often

    session_ttl_minutes: int = 720
    ci_session_ttl_minutes: int = 15

    # Where the browser goes after web login; the session cookie is set on the API origin.
    ui_url: str = ""
    cookie_secure: bool = True
