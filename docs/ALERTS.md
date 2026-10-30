# Alerts

Rekey can email an administrator, and post to a chat channel, when something needs a person, so a failed
rotation does not sit unnoticed until the old password stops working.

| Event | Sent when |
|---|---|
| `rotation_failed` | a scheduled or manual rotation failed (`rotation.fail` in the audit log) |
| `dynamic_failed` | a dynamic account could not be created, or an expired one could not be removed |
| `approval_pending` | a change to a protected environment, or a lease renewal, is waiting for a second person |
| `sealed` | an administrator sealed the server, or it has been sealed for 5 minutes since a start |
| `integrity` | the audit chain no longer verifies, or an anchored head differs from the database |

Mail never contains secret values. It names the project, environment, secret and who did it, plus the
error text Rekey already masks passwords in.

## Set it up

1. In the UI: **Alerts** (superadmin only). Enter the SMTP server and port, pick the encryption,
   a login name if your server needs one, the sender, and up to ten recipients. Tick the events you
   want and **Send alert emails**.
2. If the server needs a login, put the password in `.env` and restart:

   ```
   REKEY_SMTP_PASSWORD=...
   ```

3. Press **Save and send a test mail**. The real outcome is shown (wrong password, refused connection,
   certificate problem), so a mistake is found now and not during an incident.

Everything except the password is stored in the database and can be changed without a restart. Every
change and every test is in the audit log (`alerts.update`, `alerts.test`).

### Why the password is in `.env`

It is the one thing that is not stored in the database. A password in the database would have to be
encrypted with the key Rekey seals, which means it would stop working while the server is sealed (when
the "sealed" alert matters most) and would need re-wrapping on every root-key rotation. In `.env` it
works at all times, never appears in a backup, and is as protected as the other credentials there
(`REKEY_BOOTSTRAP_TOKEN`, the database password).

### Encryption

`STARTTLS` (usually port 587) and `SSL/TLS` (465) verify the server's certificate and host name. `None`
is accepted only when no login is set (an unauthenticated relay inside your network) or the server is
on this machine: a login is never sent unencrypted to another host.

## Chat

Optional, next to or instead of email. Create an incoming webhook in your chat tool, put its address in
`.env`, restart, then choose the format on the Alerts page:

```
REKEY_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
```

| Format | Posts |
|---|---|
| Slack, Mattermost, Rocket.Chat | `{"text": ...}` (names are escaped so nothing can ping `@channel`) |
| Discord | `{"content": ...}` with mentions disabled |
| Any URL | `{"event", "subject", "where", "what", "actor", "ts"}`, for Teams (through a Power Automate flow), a pager or your own service |

The address is a credential (anyone who has it can post to your channel), so it lives in `.env` like the
SMTP password, and is never shown. It must be `https` (plain `http` only for this machine) and redirects
are not followed. Email and chat share the event choices, the repeat rule and the hourly cap. **Save and
send a test** tries both channels and shows each one's outcome.

## Behaviour you can rely on

- **No repeats for the same problem.** A rotation that fails every 15 minutes is mailed once, then again
  after `REKEY_ALERT_REPEAT_HOURS` (default 6) if it is still failing. Approvals are separate facts, so
  each one is mailed.
- **A cap of 30 mails an hour** in total, so a flood of requests cannot turn Rekey into a mail cannon.
- **A broken mail server never breaks Rekey.** Failures are logged, shown on the Alerts page ("The last
  alert could not be sent") and the next event tries again.
- **Integrity is re-checked** every `REKEY_ALERT_CHECK_MINUTES` (default 60), by reading the whole audit
  chain, and the anchor file too when `REKEY_AUDIT_ANCHOR_FILE` is set. On a very large log, raise the
  interval.
- **Sealed** is checked every 30 seconds. With auto-unseal on, a server that comes back sealed after a
  restart is reported after `REKEY_ALERT_SEALED_AFTER_MINUTES` (default 5); a normal restart that
  unseals itself in seconds raises nothing.

## Limits

- Email and one chat webhook. For paging, forward the mail or use the generic JSON format.
- Alerts are sent by the one running API process. If it is down, nothing is sent; monitor
  `GET /health` from outside as well ([OPERATIONS.md](OPERATIONS.md)).
- Alerts that the audit log records as **denied** are not mailed (they are for Insights).
