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

- A PR comment created or edited by the verified CodeRabbit bot signals the
  trusted main-branch controller. The sender and comment author must both be
  the real bot; edits by other users and ordinary issue comments are excluded.
- The controller requires a successfully completed check from the verified
  CodeRabbit App for the latest head of an open, non-draft, owner-authored PR
  in KeyMelier. Forks, other authors and targets other than main are excluded.
  If the summary arrives before the check completes, it polls metadata for
  at most 60 seconds, without requesting reviews or reserving an attempt.
  A still-pending check is skipped; a later bot summary update can inspect it again.
- The controller re-reads the PR, the check and unresolved review threads.
  Only verified CodeRabbit findings on changed files are eligible. Resolved
  and outdated threads do not start work.
- PRs changing instruction/workflow configuration or dependency policy are
  excluded. Findings needing changes outside app.py, keymelier_core/*.py,
  static JavaScript/CSS/HTML or Python/CJS tests stay manual.
- A short, serialized claim job writes a durable attempt marker before
  inference. Each PR gets **one attempt**, including failed, cancelled,
  quota-limited or timed-out attempts. New commits do not reset it.
- Full and partial workflow reruns cannot invoke Copilot again, even when
  GitHub retains successful claim outputs. Both the job and controller require
  the first workflow attempt.

A separate source-collection runner checks out the exact head without the
Copilot secret and copies only allowed regular source/test files into an
artifact. The Copilot job never checks out the PR. It downloads this plain
source by its fixed artifact ID and validates the file allowlist again.

The CLI gets five minutes and a 25-credit soft response limit. It can read and
edit an isolated copy of those files, with no shell, GitHub MCP, web tools,
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
lint and static UI checks without the Copilot secret. The entire workflow uses
only the `issue_comment` trigger, which GitHub grants read-only access to the
default-branch cache scope. It cannot poison caches used by main or releases.
Node's automatic dependency caching is disabled as well. Manual inspection is
a separate workflow that never checks out or executes PR code. See
https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#cache-access-for-low-trust-workflow-triggers.
It deliberately avoids `check_run`, which GitHub can suppress for a PR head
already associated with Actions checks. See
https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#check_run.
The checks do not establish
physical-key acceptance, browser/native package acceptance or Windows/macOS
coverage. Existing PR CI and human review remain necessary after applying it.

A fresh publishing runner downloads the original controller and proposal by
their fixed artifact IDs, rechecks eligibility, and validates the patch without
executing PR code or tests. It never publishes a file from the mutable testing
runner. Every inter-job download uses the producing job's original artifact ID;
deleting or replacing an artifact name cannot substitute another controller or
patch. The final comment links the exact artifact ID from the publishing job.

## Inspect a handoff manually

In Actions → Inspect CodeRabbit handoff → Run workflow, select main and enter
the PR number. This only inspects the current review; it cannot reserve an
attempt, invoke Copilot or execute PR code. Only FiraSenax can dispatch it.
The executing workflow deliberately has no manual-dispatch entry point,
because manual dispatches receive main-branch cache write access by default.

No open findings, a missing secret, an already-used attempt, incomplete/stale
reviews or unsupported scope produce a skip instead of repeated requests.
Authentication, quota, CLI and validation errors fail safely; they do not fall
back to another identity or buy more usage. A stale preflight fails the worker
rather than being treated as permission to continue.

To authorize another attempt deliberately, the owner can remove the workflow's
own attempt-marker comment and wait for a new eligible CodeRabbit review to
complete. Do not automate that removal or repeatedly request reviews.
GitHub's concurrency queue can collapse pending duplicate claim jobs; a later
eligible completed review can start a fresh claim if no marker was created.

## Review and apply a tested proposal

Follow the final workflow comment's artifact link and confirm that both
**verify** and **publish** succeeded. The linked artifact is named
**tested-copilot-patch-pr-N**; a matching name alone is insufficient. Inspect
the workflow's validation logs. The intermediate **copilot-unvalidated-proposal**
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
