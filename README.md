# wazuh-rules-ci

Detection-as-code for Wazuh: a repository layout and a CI pipeline that loads every rule and
decoder with the **real Wazuh engine**, pinned to the version your manager runs, before anything
reaches that manager.

XML that parses is not a ruleset that loads. A rule with `<decoded_as>syslog</decoded_as>`
passes every XML check and then makes `wazuh-analysisd` refuse the entire ruleset with
"Invalid decoder name". The only thing that catches invalid decoder names, unknown `if_sid`
parents, bad field types and malformed regex is the engine itself. So CI runs it.

![validate](https://github.com/chiefghost47/wazuh-rules-ci/actions/workflows/validate-rules.yml/badge.svg)

## What CI checks, in order

| Step | Catches |
| :- | :- |
| **Well-formed XML, unique IDs** (`scripts/validate-xml.py`) | broken XML, a file with no rules, non-numeric or duplicate rule IDs across all files, IDs outside the range you reserve for this repository |
| **Reserved IDs** (`scripts/check-reserved-ids.sh`) | a repository rule whose ID is already taken by a rule that lives only on the manager, which the manager would reject as a duplicate at deploy time |
| **Decoder manifest** (`decoders/decoder-manifest.sha256`) | a decoder edited without regenerating the manifest: CI verifies every listed hash and that the manifest covers every decoder file. A manager-side comparison against this manifest is a separate integration you build; this gives it a reference it can trust |
| **Real engine load** | what only the loader knows: invalid decoder names, unknown `if_sid` parents, bad options, malformed regex. `wazuh-analysisd -t` runs with the exact manager version against your rules and decoders staged into a clean `/var/ossec`. CI fails on a non-zero exit and on any rule or decoder diagnostic in the captured output. The loader is silent on success, so every run also stages a deliberately broken rule (`tests/fixtures/`) and requires the engine to reject it with a visible reason: the gate proves itself each time |

Each step fails the build on its own. The last one is the one that matters.

## What this does not check

All four steps validate configuration: that the manager will accept the files. None of them
shows that a rule fires on the event it was written for. That is a detection-behaviour test,
run with `wazuh-logtest` against a running manager with synthetic positive and negative events,
and it belongs in your deploy pipeline after this gate, not in this repository.

## Layout

```
rules/        one file per rule family, ID in the file name, e.g. 100100-ssh-auth.xml
decoders/     custom decoders plus decoder-manifest.sha256
scripts/      the checks CI runs; run them locally too
docs/         what broke and why
```

Two small example families are included so the pipeline runs green out of the box: an SSH
brute-force correlation rule on top of the stock `sshd` decoder, and a custom decoder with two
rules for an application log line. Replace them with yours.

## Conventions

- **One ID range per repository.** Set `RULE_ID_MIN` and `RULE_ID_MAX` in the workflow. Anything
  outside fails. Wazuh reserves 100000 to 120000 for custom rules.
- **Reserved IDs live in `rules/reserved-rule-ids.txt`.** One ID or range per line. Export the
  IDs of every rule file on the manager that is not managed by this repository and keep that
  list current; the check only knows what you tell it.
- **Pin the engine.** `WAZUH_VERSION` in the workflow must match the manager. A newer engine
  accepting a rule proves nothing about the older one in production.
- **The decoder manifest is regenerated, never edited.** `scripts/make-decoder-manifest.sh`
  rewrites it; commit the result with the decoder change.
- **Deploy only from a green build.** The workflow is the gate: a merge to `main` with a green
  check is what you deploy, by whatever means you deploy (SSH, Ansible, a pull on the manager).

## Running the checks locally

```
export RULE_ID_MIN=100100 RULE_ID_MAX=100999   # the same values the workflow sets
python3 scripts/validate-xml.py
scripts/check-reserved-ids.sh
scripts/make-decoder-manifest.sh --check
```

The scripts default to the same range as the workflow; set the variables anyway so a local run
never disagrees with CI when the workflow changes.

The engine load needs a Wazuh manager package. The workflow shows how to install it without
starting it: a `policy-rc.d` that returns 101 keeps the postinst from starting the service, and
`wazuh-analysisd -t` runs from `/var/ossec` because it resolves its config relative to the
working directory.

## Runner note

This workflow runs on GitHub-hosted runners on purpose. It installs a package with sudo and
leaves `/var/ossec` behind, which a persistent self-hosted runner cannot absorb, and a
self-hosted runner on a public repository would execute code from any fork's pull request. If
you move it to a self-hosted runner in a private repository, run the engine step inside a
throwaway container.

## License

MIT.
