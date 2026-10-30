# Secret scanning (`rekey scan`)

## Why this exists

Storing secrets safely is half the job. The other half is making sure they do not leak out again.
The usual accidents are boring ones:

- someone pastes a `.env` file into a repository "just for now";
- a debug line prints the database URL, and the CI job log keeps it for months;
- a config file is committed with a real key instead of a placeholder.

A leaked secret is not hidden by deleting the file later: Git history, forks, caches and job logs
keep copies. The only real fix is to **rotate** the secret, so scanning is about finding the leak
early, before the copy spreads.

Most scanners guess: they look for text that *resembles* a key (`AKIA...`, long random strings).
That finds some things and misses others, and it raises many false alarms. Rekey can do something
better, because it already knows the real values. `rekey scan` looks for **those exact values**, so
a match is almost always a genuine leak.

## Use

```bash
rekey scan -p myapp -e staging .                      # a folder (the default is .)
rekey scan -p myapp -e staging src config/app.env     # specific folders and files
./build.sh 2>&1 | rekey scan -p myapp -e staging --stdin   # piped output, such as a log
```

It reads every secret you are allowed to read in that environment, then searches your files for each
value, plus its **base64** and **URL-encoded** spellings (turn that off with `--no-encodings`).
Multi-line values such as certificates are found too, including in files with Windows line endings.

Example output:

```
./config/app.env:3  secret DB_PASSWORD (/) v4
./deploy/values.yaml:12  secret API_KEY (/) v1  [base64]
Found 2 possible leaks in 2 places (41 files scanned, 8 secrets checked). Treat these secrets as exposed and rotate them.
```

**It never prints a value, or any part of one.** A finding names the secret (name, path, version),
the file and the line, so the report is safe to leave in a CI log or a ticket.

Exit codes: `0` nothing found, `1` something found, `2` the scan could not run (server error, no
login, bad path). A failed scan is never reported as clean.

### Options

| Option | Meaning |
| --- | --- |
| `PATH...` | Files or folders. Default `.`. A `-` means stdin. |
| `--stdin` | Also scan piped input. With no paths, only the piped input is scanned. |
| `--min-length N` | Skip secrets shorter than N characters (default 8). |
| `--exclude GLOB` | Skip matching files or folders; repeat for several. |
| `--no-encodings` | Look only for the exact value. |
| `-p`, `-e` | Project and environment (or `.rekey.json` / `REKEY_PROJECT`, `REKEY_ENV`). |

### What is skipped

- `.git`, `node_modules`, `.venv` and `__pycache__` folders, symbolic links, binary files (a NUL byte
  in the first 8 KB) and files over 5 MB. The summary says how many files were skipped.
- Secrets shorter than `--min-length`. A 4-character PIN matches ordinary text all the time, which
  would bury the real findings. They are listed once, by name, so you can see what was not checked.
- Secrets your login can list but not read (a narrower grant). They are named in the summary.
- Anything in `.rekeyscanignore` in the folder you scan: one glob per line, `#` for comments, and a
  trailing `/` for a folder.

```
# test data that holds fake values
fixtures/
*.snap
```

## In GitLab CI

The CLI signs in with the job's own identity token (see [GITLAB-SETUP.md](GITLAB-SETUP.md)): no
secret is stored in GitLab. Create a machine identity with a `viewer` grant on the environment and a
CI binding for the project, exactly as for `rekey run`.

```yaml
secret-scan:
  stage: test
  id_tokens:
    REKEY_JWT:
      aud: rekey
  variables:
    REKEY_SERVER: https://rekey.example.com
  script:
    - pip install "git+https://github.com/IM-TECHNO/REKEY.git#subdirectory=cli"  # or your own copy
    - rekey scan -p myapp -e staging .
```

The job fails (exit 1) when a secret is found and passes when it is clean. `REKEY_JWT` is the
variable the CLI reads for CI sign-in (`rekey run` uses it the same way).

Scanning the **log** of a build: send the output through the scanner while it is produced, or scan
the saved copy.

```yaml
build:
  id_tokens:
    REKEY_JWT:
      aud: rekey
  variables:
    REKEY_SERVER: https://rekey.example.com
  script:
    - ./build.sh 2>&1 | tee build.log
    - rekey scan -p myapp -e staging --stdin < build.log
```

To check the log of another job, download it (GitLab's job trace API, with a token that can read
the project) and pipe it in: `curl ... /jobs/$ID/trace | rekey scan -p myapp -e staging --stdin`.
Scan the secrets of the environment that job used, since only those values are known to the scanner.

## Honest limits

- **It only knows what Rekey knows.** A key that is not stored in Rekey, or belongs to another
  environment than the one you scan, cannot be found. Scan each environment that matters.
- **It finds copies, not transformations.** Encrypted, hashed, compressed, split across lines or
  concatenated values are invisible. Only the exact value, base64 (standard and URL-safe, with and
  without padding) and URL-encoding are tried. A secret embedded inside a *larger* base64 blob can
  sit at a different alignment and be missed.
- **Short values are skipped** (see above). Rekey is not a good judge of a 6-character password.
- **A match is a signal, not proof.** A value that is also ordinary text (say `production`) matches
  that text. Keep such values out of Rekey, or raise `--min-length`.
- **It cannot undo anything.** If it finds a leak, rotate the secret: Rekey's rotation features
  ([OPERATIONS.md](OPERATIONS.md)) do that on a schedule or on demand.
- Scanning reads every secret in the environment, so it is audited like any other read, and the
  login you use needs `viewer` on it. Use a dedicated CI identity rather than a person's login.
