# Auto-unseal

Rekey starts **sealed**. In that state it holds no key that can read a secret, so someone who steals a
copy of the database, a backup or the disk gets nothing readable. To use it, a few people enter their
**shares** (the default is any 3 of 5). **Auto-unseal** is an option that removes that manual step by
letting a separate key service do the unsealing for the server. This page explains what that changes,
so you can decide whether it suits you.

## What sealing protects against

Every secret is encrypted with a key for its environment. Those keys are stored encrypted by one
master key (the key-encryption key, KEK). The KEK is **never stored**: it only exists in the server's
memory after enough shares are combined. So:

| An attacker has | Without auto-unseal |
| --- | --- |
| a copy of the database or a backup | nothing readable: the KEK is not in it |
| the disk of the server while it is switched off | nothing readable |
| root on the running, unsealed server | everything in memory (sealing cannot help here) |
| one or two share holders' shares | nothing: the threshold is 3 |

The price is that after **every restart** (an upgrade, a crash, a reboot) people must be reachable to
enter shares. That is safe, but it means no unattended restarts.

## What auto-unseal changes

With auto-unseal the KEK is stored **encrypted by a key service** (a "wrapped" KEK). At start, the
server asks the key service to decrypt it and unseals itself. The key service is a separate system you
run or rent: HashiCorp Vault or OpenBao (Transit engine), or AWS KMS.

The database still holds only the *wrapped* KEK, which is useless on its own: opening it needs the key
service, and the key service answers only to a credential you restrict. So a stolen database copy is
still unreadable. What you give up is the second factor "a person must be present": anyone who can
**read the database and also make the key service answer** can now unseal Rekey.

### Who needs what, under each way of unsealing

| | An attacker needs |
| --- | --- |
| **Shares, entered by people** (default) | the database **and** any 3 of the 5 share holders |
| **Key service** (this feature) | the database **and** the ability to call the key service as Rekey (its token or IAM role, from inside the allowed network) |
| **A file of shares on the server** (`REKEY_DEV_UNSEAL_FILE`, development only) | the database **and** that file: usually one stolen disk or backup |

So the key service is much better than a file on disk, because the credential can be limited to one
host and every use shows up in the key service's own audit log, but weaker than people holding shares.
The shares **keep working** either way, as the break-glass way in if the key service is down.

Choose it when unattended restarts matter more than that second factor (small teams without a rota of
share holders, automatic security updates, an orchestrator that restarts containers). Skip it when
the data is sensitive enough that a person should always be in the loop.

## How it behaves

- It is **off** by default (`REKEY_AUTO_UNSEAL=off`). Turning it on is two steps: configure the key
  service in the server's environment, restart, then press **Turn on** on the Security page (or
  `POST /v1/sys/auto-unseal`). Enabling needs the server **unsealed**, because the KEK only exists then.
  Rekey wraps the KEK, unwraps it again and compares, so a broken key service is caught before
  anything is saved.
- At start, if a wrapped KEK is stored and the settings match it, the server unseals itself and writes
  `sys.unseal` to the audit log with the actor `auto-unseal`.
- If the key service is down or refuses, the server **stays sealed** (it never crashes) and retries every
  30 seconds. The shares still work meanwhile. Only a wrong or unreachable service is affected; a
  person entering shares at the same time is not disturbed.
- **Sealing on purpose sticks.** After `POST /v1/sys/seal` (the *Seal now* button) auto-unseal stays
  quiet until the next restart, so an emergency seal cannot be undone by the server itself.
- **Rekey** (new root key, new shares) changes the KEK, so Rekey wraps the new one right away. If the
  key service refuses, auto-unseal is switched off and the response and audit log say so; turn it on
  again once the service works. A stored key that no longer matches (the root key was replaced, or the
  configured service or key name changed) is ignored, never used.
- **Turn off** deletes the wrapped KEK. From the next start the shares are needed again.
- `GET /v1/sys/status` shows `auto_unseal` (the provider name, or empty) and the Security page shows the
  state, the key and the date it was enabled.

## Settings

All use the prefix `REKEY_`. A half-configured provider stops the server at start with a clear message.

| Setting | Meaning |
| --- | --- |
| `AUTO_UNSEAL` | `off` (default), `transit` or `aws-kms` |
| `AUTO_UNSEAL_ADDR` | transit: `https://vault.example.com:8200` (scheme, host, port only; plain `http` only for localhost) |
| `AUTO_UNSEAL_TOKEN` or `AUTO_UNSEAL_TOKEN_FILE` | transit: the token, or a file holding it (exactly one). The file is read on every call, so you can renew it without a restart |
| `AUTO_UNSEAL_KEY` | transit: the key name; aws-kms: key id, ARN or alias |
| `AUTO_UNSEAL_MOUNT` | transit: where the engine is mounted (default `transit`) |
| `AUTO_UNSEAL_NAMESPACE` | transit: namespace, if you use them |
| `AUTO_UNSEAL_REGION` | aws-kms: the region (empty = the usual AWS environment) |

`REKEY_AUTO_UNSEAL` cannot be combined with `REKEY_DEV_UNSEAL_FILE`: pick one.

## Setting up Vault or OpenBao (Transit)

```bash
vault secrets enable transit                       # or: bao secrets enable transit
vault write -f transit/keys/rekey-unseal type=aes256-gcm96
```

Give Rekey a token that can do **only** this, on **only** this key:

```hcl
# rekey-unseal.hcl
path "transit/encrypt/rekey-unseal" { capabilities = ["update"] }
path "transit/decrypt/rekey-unseal" { capabilities = ["update"] }
```

```bash
vault policy write rekey-unseal rekey-unseal.hcl
vault token create -policy=rekey-unseal -period=24h -orphan   # better: AppRole or a platform auth
```

Then in Rekey's environment:

```
REKEY_AUTO_UNSEAL=transit
REKEY_AUTO_UNSEAL_ADDR=https://vault.example.com:8200
REKEY_AUTO_UNSEAL_KEY=rekey-unseal
REKEY_AUTO_UNSEAL_TOKEN_FILE=/run/secrets/rekey-unseal-token
```

Do not use a key that Vault also uses for something else, and do not give the token `read`, `delete`
or key-management rights. Do not let someone with Vault admin rights be the only person who can reach
Rekey's database. Remember the Vault itself has to be available (and unsealed) when Rekey restarts.

## Setting up AWS KMS

Install the optional dependency (`pip install "rekey-server[aws]"`; the Docker image does not include it
by default) and create a symmetric KMS key used only for this. The server's role needs only:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Encrypt", "kms:Decrypt"],
    "Resource": "arn:aws:kms:eu-west-1:111122223333:key/<key id>"
  }]
}
```

Rekey also sends an encryption context named `rekey` with every call, so the wrapped key only opens
for this use, and it shows up in CloudTrail. Use an instance or task role, not long-lived access keys. Settings: `REKEY_AUTO_UNSEAL=aws-kms`, `REKEY_AUTO_UNSEAL_KEY=alias/rekey-unseal`,
`REKEY_AUTO_UNSEAL_REGION=eu-west-1`.

## Recommendations

- **Use a dedicated key** for this and nothing else, so its logs mean one thing.
- **Restrict who can call it**: by network (only the Rekey host), by identity (one role or token), and
  keep the token short-lived or renewable.
- **Watch the key service's audit log.** Every unseal is one Decrypt call. An unexpected Decrypt from a
  different address, or at a time nobody restarted Rekey, is the alarm you want.
- **Keep the shares anyway**, split among different people as before. They are the break-glass way in
  if the key service is lost, and `rekey` still works with them.
- **Back up the key service's key** the way you back up anything that unlocks everything. If it is
  destroyed and you did not enable it from a state you can recover, the shares are your only way in.
- Do not use auto-unseal and `REKEY_DEV_UNSEAL_FILE` together (the server refuses), and do not use the
  dev file in production at all.

## Adding another provider

A provider is one small class in `server/src/rekey/autounseal.py` with an async `wrap(plaintext,
context)` and `unwrap(blob, context)`, plus a `key_ref` that names the key. GCP Cloud KMS and Azure
Key Vault fit the same shape: add the class, a branch in `check_config` and `build_provider`, and its
settings.
