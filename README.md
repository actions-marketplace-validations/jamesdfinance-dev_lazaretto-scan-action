# Lazaretto Scan (GitHub Action)

Fail the build when a dependency you actually pinned is known malware.

The action reads your lockfile and checks every pinned version against published
malicious-package advisories (OSV / OpenSSF). **That check is free, needs no API
key, and is one request for your whole dependency tree.** An optional deep
behavioral scan is available on top, for artifacts you want analyzed rather than
just identified.

This catches the case that actually happens: `chalk@5.6.1`, `debug@4.4.2` and
`@ledgerhq/connect-kit@1.1.6` were compromised releases of legitimate, widely
used packages. Their clean releases sit either side of the bad one, so the
version in your lockfile is what decides whether you are affected.

## See it on your project first, in one line

Before wiring it into CI, run the same check locally. No install, no account,
no key:

```bash
curl -s https://lazaretto.dev/check --data-binary @package-lock.json
```

## Quick start

No secret to configure. Add this and a malicious pin fails the build:

```yaml
name: Lazaretto
on:
  pull_request:
    paths: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']
permissions:
  contents: read
  pull-requests: write # so the action can post its comment
jobs:
  deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: jamesdfinance-dev/lazaretto-scan-action@v1
```

Supported lockfiles, auto-detected: `package-lock.json`, `npm-shrinkwrap.json`,
`yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5, v6, v9).

## Adding the deep behavioral scan

The lockfile check answers "is this package known malware". The deep scan
answers "what does this artifact actually do": credential access, exfiltration,
obfuscation, install scripts, prompt injection aimed at an agent, with the file
and line for each signal. That part uses credits, so it needs a key.

```yaml
      - uses: jamesdfinance-dev/lazaretto-scan-action@v1
        with:
          api-key: ${{ secrets.LAZARETTO_API_KEY }}
```

With a key and no explicit `targets`, the action deep-scans your **direct**
dependencies at the exact versions in `package-lock.json`. You can also name
targets yourself:

```yaml
      - uses: jamesdfinance-dev/lazaretto-scan-action@v1
        with:
          api-key: ${{ secrets.LAZARETTO_API_KEY }}
          targets: |
            npm_package:left-pad@1.3.0
            github_repo:some-org/some-skill
```

Get a free developer key (a daily scan allowance, no signup, no card):

```bash
curl -s -X POST https://lazaretto.dev/v1/trial   # returns an api_key
```

Store it as a repo secret. For CI volume, buy a capacity pack at
https://lazaretto.dev/#pricing. An agent can also pay per call over x402.

## What it reports

On a pull request the action posts one sticky comment (created once, updated on
each run), and always writes a job summary. Both show which pinned versions are
known malware with a link to the advisory, and, when the deep scan ran, the
verdict and `risk` level per target.

Set `comment: false` to turn the comment off.

## Inputs

| input | default | description |
| --- | --- | --- |
| `lockfile` | `auto` | Lockfile to check. `auto` finds the usual names in the workspace root. Set `""` to skip. No API key needed. |
| `api-key` | (none) | Key for the optional deep behavioral scan. Not needed for the lockfile check. |
| `targets` | (none) | Newline list of `type:ref` for the deep scan. `type` is `npm_package`, `github_repo`, `clawhub_skill`, or `raw_url`. |
| `package-json` | `package.json` | Direct deps the deep scan covers when `targets` is empty. Versions come from the lockfile. |
| `fail-on` | `malicious` | Fail the build at this level: `malicious`, `flagged`, or `never`. |
| `comment` | `true` | On a PR, post/update a sticky comment (needs `pull-requests: write`). |
| `github-token` | workflow token | Token used to post the comment. |
| `base-url` | `https://lazaretto.dev` | API base URL. |

## Outputs

| output | description |
| --- | --- |
| `malicious-count` | Number of pinned versions found to be known malware. |
| `worst-verdict` | Worst deep-scan verdict, or `unscanned` if the deep scan did not run. |

## What it does not claim

A known-malware hit fails the build at any `fail-on` except `never`: that is a
published advisory naming an exact version, not a heuristic.

Everything else is reported honestly rather than optimistically:

- Versions we could not check are listed separately. An empty malicious list is
  an all-clear only when nothing is sitting in the unverified column.
- Entries with no published identity (`file:`, `link:`, `workspace:`, git) are
  counted and named as skipped, because "we checked 1325 of your 1432 entries"
  and "you are clean" are different statements.
- If the service is unreachable the step warns loudly and does not fail your
  build, but it does not report a pass either.
- Only exact versions are checked. A range like `^5.0.0` has no honest answer,
  since the compromised release usually sits between clean ones.

`clear` means no known-bad match and no rule fired. It is not a statement that a
package is risk-free.

## Cost

The lockfile check is free and unmetered (rate limited per IP). Only the
optional deep scan uses credits, one per target per run. Gate the job on
lockfile changes, as in the quick start, so it runs when something changed.

## License

MIT. The Lazaretto service and its detection engine are separate and proprietary.
