# Connecting Rekey to GitLab

Tested against a real GitLab, and against a stand-in one for the automated tests
(`server/tests/fake_idp.py`, `scripts/e2e_local.py`).

## 0. How the pieces are reached

The browser, the CLI and CI jobs all use **one host**. In a real deployment an edge proxy (the
bundled nginx, or your Kubernetes Ingress) sends `/v1/*` to the API and everything else to the web UI,
so the session cookie is first-party and no CORS is needed. The redirect URI below is that host.
(For local development only, the Next.js dev server proxies `/v1/*` itself.) The proxy must
overwrite `X-Forwarded-For`; see [OPERATIONS.md](OPERATIONS.md).

## 1. Register the application (people login)

GitLab -> Admin or group -> Applications -> new application:

- Redirect URI: `https://<rekey UI host>/v1/auth/oidc/callback`
- Confidential: yes. Scopes: `openid`, `profile`, `email`.
- Copy the Application ID and Secret.

## 2. Server settings

```
REKEY_OIDC_ISSUER=https://gitlab.example.com
REKEY_OIDC_CLIENT_ID=<application id>
REKEY_OIDC_CLIENT_SECRET=<secret>
REKEY_OIDC_REDIRECT_URI=https://<rekey UI host>/v1/auth/oidc/callback
REKEY_SUPERADMIN_SUBJECTS=<your GitLab user id>   # comma separated; see below
REKEY_OIDC_REQUIRED_GROUP=acme        # optional: only members of this group can log in
REKEY_CI_AUDIENCE=rekey
REKEY_UI_URL=https://<rekey ui host>/     # where the browser lands after web login
```

- The issuer must be `https` (loopback is allowed for local testing only).
- GitLab returns group membership in the ID token as `groups_direct` (Rekey also reads `groups`).
  Use the group's full path. If the required-group check rejects everyone, inspect a real ID token's
  claims.
- A new GitLab user can log in but can do nothing until a superadmin grants access.
- **Superadmins** are matched by GitLab **numeric user id** (the OIDC `sub`), never by username, since
  a username can be renamed or re-registered. Log in once, then read your id from `GET /v1/auth/whoami`
  (`subject`), add it to `REKEY_SUPERADMIN_SUBJECTS` and restart. Admins see the Access control,
  Audit log and Insights pages. CI sessions are never superadmin. The bootstrap token stays as
  break-glass.

## 3. People: the CLI

```
rekey login --server https://<rekey host>
rekey run -p myapp -e dev -- npm start
```

`.rekey.json` in a repo can hold `{"project": "myapp", "env": "dev"}` so the flags are optional.

## 4. Pipelines: GitLab CI ID tokens

Create a machine identity, give it a grant, and bind it to the project and branch:

```
POST /v1/identities                        {"name": "ci-myapp-api"}
POST /v1/identities/ci-myapp-api/grants  {"project": "myapp", "environment": "staging", "role": "viewer"}
POST /v1/identities/ci-myapp-api/ci-bindings
     {"project_path": "acme/myapp-api", "project_id": "42", "ref": "main", "protected_only": true}
```

**Pin `project_id`** (GitLab: Settings > General). A project path can be freed and re-registered by
someone else after a rename or deletion; the numeric id cannot. Without it, any GitLab project that
ends up at that path matches the binding. The Access page flags bindings that are not pinned.

`.gitlab-ci.yml`:

```yaml
deploy:
  id_tokens:
    REKEY_JWT:
      aud: rekey
  variables:
    REKEY_SERVER: https://<rekey host>
  script:
    - rekey run -p myapp -e staging -- ./deploy.sh
```

No secret is stored in GitLab: the job's token is exchanged for a 15-minute Rekey session. With
`protected_only` the binding only works on protected branches or tags. An exact `ref` beats `*`.

## Security notes

- Web sessions use an HttpOnly, SameSite=Strict cookie, and state-changing requests also need the
  header `X-Rekey-Client: web`. A cookie tied to the browser that started the login blocks login CSRF.
- The CLI session token is stored in the user's config directory with owner-only permissions.
- Disabling an identity (`POST /v1/identities/{name}/disable`) deletes its sessions at once.
- Login, callback, code exchange, CI login and unseal are rate limited per IP (see OPERATIONS.md).
