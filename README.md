# Lazaretto Scan

Fail the build when a dependency you pinned is known malware, and behaviorally scan the versions each pull request **adds**.

The dependency identity check is **free, unlimited, and needs no API key**. Copy this in and you are done:

```yaml
name: Lazaretto
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jamesdfinance-dev/lazaretto-scan-action@v2
```

That checks every exactly pinned version in your `package-lock.json`, `yarn.lock` or `pnpm-lock.yaml` against published malicious-package advisories (OSV and OpenSSF), fails the build on a match, and leaves a single sticky comment on the PR that updates itself.

## Adding the behavioral scan

The identity check answers *"is anything I pinned known malware"*. It cannot answer *"what does this code actually do"*, and it is weakest exactly when a brand-new malicious release lands, because there is no advisory to match yet.

Add one line to answer that too:

```yaml
      - uses: jamesdfinance-dev/lazaretto-scan-action@v2
        with:
          api-key: ${{ secrets.LAZARETTO_API_KEY }}
```

Everything else is inferred. On a pull request it scans **only the dependency versions the PR adds**, so a PR that changes no dependencies scans nothing and costs nothing, and a Dependabot or Renovate PR costs one credit per new version. On a `schedule` or a manual run it scans the whole tree.

Get a key:

```bash
curl -X POST https://lazaretto.dev/v1/trial
```

Then add it as a repository secret named `LAZARETTO_API_KEY`.

### The weekly whole-tree scan

Per-PR scanning only ever sees what changes. This covers everything you already have:

```yaml
name: Lazaretto weekly
on:
  schedule: [{ cron: '17 4 * * 1' }]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jamesdfinance-dev/lazaretto-scan-action@v2
        with:
          api-key: ${{ secrets.LAZARETTO_API_KEY }}
          max-packages: '250'
```

## Cost

One credit per package that produces a verdict. A package that errors is never billed. `max-packages` is a hard ceiling per run, defaulting to **250**, so a first install cannot produce a surprise bill; the run says plainly when it capped and what it skipped.

`credits-spent` is an output, so you can assert on it.

## Inputs

| input | default | what it does |
| --- | --- | --- |
| `lockfile` | `auto` | Lockfile to check. `auto` finds package-lock.json, yarn.lock or pnpm-lock.yaml. `""` skips. |
| `api-key` | `''` | Turns on the behavioral scan. Without it only the free identity check runs. |
| `deep-scan` | `auto` | `auto` scans what a PR adds, and the whole tree on a schedule or manual run. Force with `changed`, `all` or `none`. |
| `max-packages` | `250` | Hard ceiling on packages scanned per run. One credit each. |
| `fail-on` | `malicious` | Fail at `malicious`, `flagged`, or `never`. |
| `comment` | `true` | Post and update a sticky PR comment. Needs `pull-requests: write`. |
| `github-token` | workflow token | Used to post the comment and read the base lockfile. |
| `base-url` | `https://lazaretto.dev` | API base URL. |

## Outputs

| output | meaning |
| --- | --- |
| `malicious-count` | Pinned versions found to be known malware. |
| `worst-verdict` | `malicious`, `flagged`, `clear`, `error` or `unscanned`. |
| `added-count` | Dependency versions this PR adds. |
| `credits-spent` | Credits billed by this run. |

## What it does not do

A known-malware match is a published advisory saying that exact version is malware, so it fails the build at any threshold except `never`. Everything else is an automated signal with evidence attached, not a warranty. A `clear` result means nothing matched and no rule fired; it is not a statement that an artifact carries no risk.

If our API is unreachable the step warns loudly and does not report a clean run. An outage is not an all-clear.

Reading the base lockfile on a PR uses the GitHub API rather than git history, so a shallow checkout does not silently disable the diff.

---

[Lazaretto](https://lazaretto.dev) · [API docs](https://lazaretto.dev/docs/api) · [real incidents we catch](https://lazaretto.dev/caught)
