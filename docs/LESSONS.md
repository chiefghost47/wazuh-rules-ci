# Lessons from running this

## XML validity is not loadability

Picture a rule using `<decoded_as>syslog</decoded_as>`. It passes every XML check. Then
`wazuh-analysisd` refuses to load the whole ruleset: "Invalid decoder name: 'syslog'". If CI
only checks XML, the first place that can catch it is the manager itself, which is production.
Running the engine in CI is the step that matters.

## The Wazuh container image cannot run `analysisd -t`

The image ships no `etc/internal_options.conf`; its entrypoint creates that file at start.
`--entrypoint /bin/bash`, which you need to run analysisd directly, is exactly what skips it,
and analysisd dies with "Could not open file etc/internal_options.conf". Installing the
`wazuh-manager` package on a plain Ubuntu gives a complete, canonical `/var/ossec` that is
byte-for-byte what a manager runs.

## Install the package without starting the service

A `/usr/sbin/policy-rc.d` that exits 101 stops the postinst from starting the manager. The
check only needs the ruleset loaded, never a running manager.

## `/var/ossec` is not traversable by an unprivileged user

`etc` is `drwxrwx--- wazuh:wazuh` and `bin` is `drwxr-x--- root:wazuh`. An unprivileged
`test -x /var/ossec/bin/wazuh-analysisd` reports the binary as missing, and an unprivileged glob
over `/var/ossec/etc/rules` silently matches nothing. Both produced "no such file" failures that
were really permission failures. Every test and glob there runs under sudo.

## `cd` inside sudo

analysisd resolves `etc/internal_options.conf` relative to the working directory, so it must run
from `/var/ossec`. `cd /var/ossec && sudo ./bin/wazuh-analysisd -t` fails on the `cd`, before
sudo is reached, because the runner user cannot enter the directory. The `cd` has to happen
inside `sudo sh -c`.

## Don't filter the diagnostics

The failure path once piped the analysisd log through `grep -iE 'error|critical|invalid'`.
Under `bash -e` with `pipefail`, grep exits 1 when it matches nothing, so a failure whose text
contained none of those words killed the diagnostics before they printed, leaving a red step
with no explanation. Print the log verbatim. It is a few dozen lines.

## The manager has rules the repository does not know about

A manager that has grown by hand usually carries rule files the repository never saw. A new
repository rule can then pass every repository-side check and be rejected by the manager as a
duplicate id. The reserved-ID list is the repository's view of the manager's namespace; it is
only as current as the last export, so export it again before assigning a new block.

## A drift check is only as good as its reference

If you compare the decoders a manager runs against a manifest of hashes, the manifest has to
be generated from the repository and verified there, or the manager ends up reporting drift that
is really a stale manifest. CI here verifies that the committed manifest matches the decoder
files and covers all of them. The manager-side comparison is a separate integration you build;
this repository gives it a reference it can trust.

## Zero alerts never proves a rule is broken

It is easy to declare a rule broken because it has never fired, when the event it matches has
simply not happened. Before reporting a rule as dead, generate the event it should match and
watch for the alert. A rule that loads and has fired once is a different claim from a rule that
loads.
