# CodeRabbit → Copilot patch proposals

The workflow in ../workflows/coderabbit-copilot.yml hands current CodeRabbit
findings to Copilot CLI using the owner's existing Copilot allowance. It produces
a bounded patch and a test result for human review. It never pushes source
changes, merges a PR or invokes CodeRabbit Agent/Autofix.

## Enable the workflow

The workflow must first be reviewed and merged into main. Without the secret
below it performs inspection only and cannot run inference or consume a PR's
correction attempt.

1. Create a **new fine-grained personal access token** in GitHub:
   https://github.com/settings/personal-access-tokens/new
   Use the personal account FiraSenax as resource owner, select only KeyMelier
   under repository access, choose an expiry, and grant the **account permission
   Copilot Requests**. No Contents write, Pull requests write, workflow-write or
   administration permission is needed by this token.
2. Store it directly in the repository's Actions secrets as
   **COPILOT_REVIEW_TOKEN**:
   https://github.com/FiraSenax/KeyMelier/settings/secrets/actions/new
   Do not put the value in a PR, issue, source file or chat. Existing OAuth
   logins are not copied into Actions, and OAuth tokens are rejected as this
   workflow's secret.
3. Keep Copilot's additional-usage budget at **$0** with additional usage
   disabled. The workflow does not change billing or purchase credits. The
   CLI's 25-AI-credit response limit is a **soft limit**, not a guaranteed bill
   ceiling; the account's no-overage setting is the spending boundary.

Adding the secret enables the automatic handoff for future eligible reviews.
Removing the secret disables new handoffs. Already-running jobs must be
cancelled separately. No CodeRabbit API key or new subscription is required.

GitHub's token setup:
https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli

## What starts a run

- A successfully completed check from the verified CodeRabbit App, for the
  latest head of exactly one open, non-draft, owner-authored PR in KeyMelier.
  Forks, other authors and targets other than main are excluded.
- The controller re-reads the PR, the check and unresolved review threads.
  Only verified CodeRabbit findings on changed files are eligible. Resolved
  and outdated threads do not start work.
- PRs changing instruction/workflow configuration or dependency policy are
  excluded. Findings needing changes outside app.py, keymelier_core/*.py,
  static JavaScript/CSS/HTML or Python/CJS tests stay manual.
- A short, serialized claim job writes a durable attempt marker before
  inference. Each PR gets **one attempt**, including failed, cancelled,
  quota-limited or timed-out attempts. New commits do not reset it.

The CLI gets five minutes and a 25-credit soft response limit. It can read and
edit an isolated copy of source/test files, with no shell, GitHub MCP, web tools,
project hooks, repository metadata, PR-provided instructions or subagents.
Trusted main-branch project rules are included explicitly. It receives only the
Copilot Requests token, not the Actions job token or unrelated credentials.
The CLI and transitive packages are version/integrity locked here; npm lifecycle
scripts and Copilot auto-updates are disabled.

The controller rejects deletions, symlinks, binary content, unrelated source
edits, new source modules, and changes exceeding eight files, 400 changed lines
or a 100-KB patch. New regression tests are allowed. It never executes PR code
with the Copilot secret present.

A separate runner applies the proposal to its exact head and runs backend,
lint and static UI checks without the Copilot secret. It does not establish
physical-key acceptance, browser/native package acceptance or Windows/macOS
coverage. Existing PR CI and human review remain necessary after applying it.

## Inspect or request a handoff manually

In Actions → CodeRabbit to Copilot → Run workflow, select main, enter the PR
number and leave **execute** unchecked for an inspection with no claim or
inference. To use an eligible PR's one attempt, check execute. Only FiraSenax can
dispatch it; the same head/finding/policy guards apply.

No open findings, a missing secret, an already-used attempt, incomplete/stale
reviews or unsupported scope produce a skip instead of repeated requests.
Authentication, quota, CLI and validation errors fail safely; they do not fall
back to another identity or buy more usage. A stale preflight fails the worker
rather than being treated as permission to continue.

To authorize another attempt deliberately, the owner can remove the workflow's
own attempt-marker comment, then inspect and dispatch again. Do not automate
that removal. GitHub's concurrency queue can collapse pending duplicate claim
jobs; inspection/manual dispatch remains the fallback.

## Review and apply a tested proposal

Use only the artifact named **tested-copilot-patch-pr-N**, and inspect the
workflow's validation logs. The intermediate **copilot-unvalidated-proposal**
artifact is not an accepted/tested fix. Raw model transcripts are not uploaded.
Intermediate artifacts expire after one day; tested proposals after seven days.

In a clean worktree for the PR, first confirm that its HEAD still equals
head_sha in context.json. Review fix.patch, then:

    git apply --check /absolute/path/to/fix.patch
    git apply /absolute/path/to/fix.patch

Run the affected checks, inspect the resulting diff, and commit/push only after
review. That ordinary authorized push triggers existing CI and CodeRabbit
reviews, subject to their plan and rate limits. The automated proposal itself
does not trigger an endless review/fix loop.

## Maintenance and verification

The trusted controller is tools/coderabbit_copilot.py. Run:

    python -m unittest discover -s tests -p test_coderabbit_copilot.py -v
    ruff check tools/coderabbit_copilot.py tests/test_coderabbit_copilot.py
    git diff --check

The synthetic tests do not call Copilot or use real credentials. They cover
review identity/freshness, author/repository scope, a consumed attempt across
commits, hostile review text, secret isolation, patch limits and real git-apply
roundtrips. Review controller/permission/lockfile changes separately; these
files are never an allowed automatic fix target.
