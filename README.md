# AeroTrust

## Zero Trust Security Gateway for GitHub Contributions

A small Cloudflare Workers + D1 prototype that evaluates GitHub pull requests before they are trusted with sensitive CI/CD behavior.

### Core idea

External contributions should not automatically receive the same trust as trusted repository code.

AeroTrust evaluates:
- contribution source
- whether it comes from an external fork
- changed files
- workflow changes
- deployment/infrastructure changes

It returns:

- ALLOW
- REVIEW
- BLOCK

and stores an auditable decision in D1.

## Architecture

GitHub Pull Request
        |
        v
GitHub Webhook
        |
        v
Cloudflare Worker
        |
        v
AeroTrust Policy Engine
        |
        +------> ALLOW / REVIEW / BLOCK
        |
        v
D1 Audit Log

## Demo without GitHub

After configuring D1 and running the Worker:

```bash
curl -X POST http://localhost:8787/simulate \
  -H "Content-Type: application/json" \
  -d '{"isFork":true,"repository":"demo/app","prNumber":42,"contributor":"alice","files":["src/app.js","README.md"]}'
```

Expected: ALLOW.

Try a workflow modification:

```bash
curl -X POST http://localhost:8787/simulate \
  -H "Content-Type: application/json" \
  -d '{"isFork":true,"repository":"demo/app","prNumber":43,"contributor":"alice","files":[".github/workflows/deploy.yml"]}'
```

Expected: BLOCK.

Try deployment infrastructure:

```bash
curl -X POST http://localhost:8787/simulate \
  -H "Content-Type: application/json" \
  -d '{"isFork":true,"repository":"demo/app","prNumber":44,"contributor":"alice","files":["terraform/main.tf"]}'
```

Expected: REVIEW.

## 3-hour setup

### 1. Install Node.js

Use Node.js 20+.

### 2. Install dependencies

```bash
npm install
```

### 3. Login to Cloudflare

```bash
npx wrangler login
```

### 4. Create D1

```bash
npx wrangler d1 create aerotrust-db
```

Copy the returned database ID into `wrangler.toml`.

### 5. Create the table

```bash
npx wrangler d1 migrations apply aerotrust-db --local
```

For the deployed database:

```bash
npx wrangler d1 migrations apply aerotrust-db --remote
```

### 6. Add secrets

```bash
npx wrangler secret put GITHUB_WEBHOOK_SECRET
npx wrangler secret put GITHUB_TOKEN
```

For the first demo, you can skip GitHub integration and use `/simulate`.

### 7. Run locally

```bash
npm run dev
```

Open:

```text
http://localhost:8787
```

## GitHub webhook

Create a webhook in the repository:

Settings → Webhooks → Add webhook

Payload URL:

```text
https://YOUR-WORKER.workers.dev/webhook/github
```

Content type:

```text
application/json
```

Secret:

Use the same value stored in `GITHUB_WEBHOOK_SECRET`.

Select these webhook events:

- **Pull requests** — subscribe to opened, reopened, synchronize, and ready_for_review.
- **Pull request reviews** — subscribe to submitted.

The Worker verifies the HMAC signature, retrieves changed file paths, evaluates policy, writes the decision to D1, and publishes a GitHub Check named **AeroTrust Policy** on the PR head commit.

### GitHub Check enforcement

Create a fine-grained personal access token for the target repository with:
- **Pull requests: Read**
- **Checks: Read and write**
- **Metadata: Read** (normally selected automatically)

Store it as a Worker secret:

```bash
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put GITHUB_WEBHOOK_SECRET
```

The check conclusion maps to policy:
- **ALLOW** → success
- **REVIEW** → action_required (merge remains blocked when this is a required check)
- **BLOCK** → failure

For actual merge protection, open the target repository's Settings → Rules → Rulesets (or Branch protection rules), target the protected branch, and require the status check **AeroTrust Policy**. Without that repository rule, a failing check is visible but GitHub may still allow merging.

For a REVIEW decision, a maintainer submits an **Approve** or **Request changes** review in GitHub. The pull_request_review webhook re-evaluates the current PR; approval clears only a REVIEW finding, while BLOCK remains blocked. A new commit triggers re-evaluation.

If the token is missing or GitHub rejects the Check API request, AeroTrust still records the decision in D1 and returns the Check publishing error in the webhook response; it does not claim merge enforcement succeeded.

## Important

This is a portfolio/research prototype, not a replacement for GitHub's native security controls.

The key research/engineering idea is policy-based Zero Trust evaluation of untrusted contributions before sensitive CI/CD actions are trusted.

## Demo policy

1. External fork + normal code → ALLOW
2. External fork + deployment/infrastructure change → REVIEW
3. External fork + GitHub Actions workflow modification → BLOCK
