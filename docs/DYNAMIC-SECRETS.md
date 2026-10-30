# Dynamic secrets

## The idea

A normal secret is a **shared** password: everyone who needs the database uses the same one, it lives
for months, and when it leaks you cannot tell who leaked it or which copy to cancel.

A **dynamic secret** turns that around. Each time a person, a script or a pipeline needs the database,
Rekey creates a **brand new database account** for them, with a random name and password, that
**deletes itself** after a short time (an hour by default). Nothing long-lived is left to steal.

| | Shared password | Dynamic account |
|---|---|---|
| Lifetime | months | minutes to hours |
| Who used it | anyone, unknown | one named requester, in the audit log |
| If it leaks | change it everywhere, hope nothing breaks | it is already expiring; revoke that one account |
| Stored by Rekey | yes, encrypted | **no**, shown once |

## How it works

1. A superadmin defines a **dynamic role**: which database server, which admin account Rekey may use
   to create accounts (its password is a normal Rekey secret), and **which existing database role the
   new accounts inherit their rights from** (for example `app_readonly`).
2. Anyone who can **read** that environment asks for credentials (UI, `rekey dynamic creds`, or
   `rekey dynamic run`). Rekey creates the account, answers with the username and password **once**, and
   records only the account name, who asked and when it expires.
3. At the expiry time a background task connects with the admin account, **ends the account's open
   connections** and drops it. On PostgreSQL the account is also created `VALID UNTIL` that time, so the
   database refuses it by itself even if Rekey is down. If the removal fails, Rekey keeps retrying and
   shows the error.
4. You can revoke an account early. Deleting a role first removes every live account it issued.

The new accounts get **only** membership in the role you named, so the rights are decided by you in the
database, not by anything a requester can type. No SQL is ever pasted together by Rekey: names and
passwords are quoted by the database server itself.

## Set it up

1. In the database, create the role that holds the permissions and an admin that may create accounts:

   ```sql
   -- PostgreSQL
   CREATE ROLE app_readonly NOLOGIN;
   GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;
   CREATE ROLE rekey_admin LOGIN CREATEROLE PASSWORD '...';
   GRANT app_readonly TO rekey_admin WITH ADMIN OPTION;   -- lets it hand the role to new accounts
   GRANT pg_signal_backend TO rekey_admin;                -- lets it end an expired account's sessions
   ```

   ```sql
   -- MySQL 8
   CREATE ROLE 'app_readonly';
   GRANT SELECT ON appdb.* TO 'app_readonly';
   CREATE USER 'rekey_admin'@'%' IDENTIFIED BY '...';
   GRANT CREATE USER, PROCESS, CONNECTION_ADMIN, ROLE_ADMIN ON *.* TO 'rekey_admin'@'%';
   GRANT 'app_readonly' TO 'rekey_admin'@'%' WITH ADMIN OPTION;
   ```

2. Store the admin's password as a Rekey secret in the environment (for example `DB_ADMIN_PASSWORD`).
3. Add the role: **Dynamic secrets** in the sidebar, or

   ```bash
   curl -X POST "$REKEY/v1/projects/app/envs/prod/dynamic" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{
       "name": "readonly", "kind": "postgres", "host": "db.internal", "database": "appdb",
       "admin_user": "rekey_admin", "admin_secret_name": "DB_ADMIN_PASSWORD",
       "member_of": "app_readonly", "default_ttl_minutes": 60, "max_ttl_minutes": 480 }'
   ```

## Use it

```bash
rekey dynamic creds -p app -e prod readonly                 # prints PGUSER/PGPASSWORD/... once
rekey dynamic creds -p app -e prod readonly --format url    # postgresql://user:pass@host:5432/db
rekey dynamic run   -p app -e prod readonly -- psql -c 'select now()'   # account lives only for the command
rekey dynamic leases -p app -e prod readonly                # your live accounts
rekey dynamic revoke -p app -e prod readonly <lease-id>
```

`dynamic run` is the safest form: the account exists only while your command runs and is revoked as soon
as it ends. In GitLab CI the pipeline logs in with its ID token as usual (see
[GITLAB-SETUP.md](GITLAB-SETUP.md)) and calls `rekey dynamic run`.

## Renewing an account

A job that runs longer than its account would fail halfway. Instead of asking for a very long life up
front, a role can allow renewal. Its **renewal** setting is one of:

- `off` (the default): an account lives for the time it was given, then it is removed.
- `self`: the person (or pipeline) that asked can extend its own account.
- `approval`: the request waits until someone else approves it, the same idea as approvals for protected
  environments. A superadmin's own renewals apply directly (and are audited).

Whatever the setting, an account can **never live longer than the role's longest life
(`max_ttl_minutes`) counted from when it was created**. Renewing moves the end to "now plus the time you
ask for" but stops at that ceiling, so a stolen or forgotten account cannot be kept alive forever.
After the ceiling, ask for a new account.

```bash
rekey dynamic renew -p app -e prod readonly <lease-id> --ttl 60 --note "long migration"
rekey dynamic run   -p app -e prod --renew readonly -- ./nightly-import.sh   # renews while it runs
rekey dynamic renewals                    # requests you made, or can decide
rekey dynamic approve <request-id>        # you cannot approve your own
rekey dynamic reject  <request-id> --note "use the batch role instead"
rekey dynamic cancel  <request-id>        # withdraw yours
```

`dynamic run --renew` checks the account every few seconds and asks for more time shortly before it ends.
With `approval` it asks once, says so on stderr, and carries on checking, so an approval that arrives
while the command runs is picked up. It stops asking, with a message, when renewal is off or the ceiling
is reached. The UI has the same on the **Dynamic secrets** page: a Renew button next to each account and a
"Waiting for approval" box.

Who decides: a superadmin, or someone holding the `admin` role on that environment. Nobody decides their
own request. If the account is revoked or expires while a request is waiting, the request is closed as
expired. On PostgreSQL the database's own `VALID UNTIL` moves with the renewal; MySQL has no such setting,
so there Rekey's clean-up task is the only timer. Audit actions: `dynamic.renew`, `dynamic.renew-request`,
`dynamic.renew-approve`, `dynamic.renew-reject`, `dynamic.renew-cancel`.

## Rules and limits

- **Who may ask:** anyone with at least `viewer` on the environment (the same bar as reading a secret).
  Everyone sees only their own leases; superadmins see all. Every request, refusal, expiry and failure is
  in the audit log (with the account name, never the password).
- **Limits per role:** a default and a maximum lifetime (up to 30 days) and a cap on live accounts
  (default 20) so a runaway script cannot fill the database with accounts.
- **Sealed server:** nothing can be created, and nothing is removed until it is unsealed again (the
  admin password is a secret). Expired PostgreSQL accounts are still refused by the database meanwhile;
  MySQL has no such setting, so keep lifetimes short there.
- **Don't let these accounts own things.** An account that creates tables owns them, and the database
  will refuse to drop it. Give the rights through the role and use a normal, long-lived owner account
  for schema changes.
- **Renewal is off unless you turn it on** per role (see above); then ask again for a new account once
  the ceiling is reached.
- **MySQL** uses `information_schema.processlist` to end open sessions; MySQL has marked it deprecated
  in favour of `performance_schema.processlist`, but both need the same privilege.
- Tested against real PostgreSQL 17 and MySQL 8 servers.
