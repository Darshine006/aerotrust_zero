const json = (data, status = 200) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8"
    }
  });

/* =========================================================
   GitHub Webhook Signature Verification
   ========================================================= */

async function verifyGithubSignature(secret, body, signature) {
  if (!secret || !signature?.startsWith("sha256=")) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const receivedHex = signature.slice("sha256=".length);

  // GitHub SHA-256 HMAC signatures are 64 hexadecimal characters
  if (!/^[0-9a-fA-F]{64}$/.test(receivedHex)) {
    return false;
  }

  const received = new Uint8Array(
    receivedHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
  );

  return crypto.subtle.verify(
    "HMAC",
    key,
    received,
    new TextEncoder().encode(body)
  );
}

/* =========================================================
   AeroTrust Policy Engine
   ========================================================= */

function evaluatePolicy({ isFork, contributor, files }) {
  const workflowFiles = files.filter(f =>
    f.toLowerCase().startsWith(".github/workflows/")
  );

  const sensitiveFiles = files.filter(f => {
    const p = f.toLowerCase();

    return (
      p.includes("deploy") ||
      p.includes("terraform") ||
      p.includes("kubernetes") ||
      p.includes("infra/") ||
      p.endsWith("dockerfile")
    );
  });

  // RULE 1:
  // External fork + GitHub Actions workflow change
  // = BLOCK
  if (isFork && workflowFiles.length > 0) {
    return {
      decision: "BLOCK",

      reason:
        "External fork modified a GitHub Actions workflow. " +
        "Untrusted code must not automatically change privileged CI/CD behavior.",

      signals: {
        external_fork: true,
        workflow_change: true,
        sensitive_change: sensitiveFiles.length > 0
      }
    };
  }

  // RULE 2:
  // External fork + infrastructure/deployment change
  // = REVIEW
  if (isFork && sensitiveFiles.length > 0) {
    return {
      decision: "REVIEW",

      reason:
        "External fork modified deployment or infrastructure-related files. " +
        "Manual review is required before privileged CI/CD actions.",

      signals: {
        external_fork: true,
        workflow_change: false,
        sensitive_change: true
      }
    };
  }

  // RULE 3:
  // Everything else
  // = ALLOW
  return {
    decision: "ALLOW",

    reason:
      "No high-risk policy condition was detected for this contribution.",

    signals: {
      external_fork: !!isFork,
      workflow_change: workflowFiles.length > 0,
      sensitive_change: sensitiveFiles.length > 0
    }
  };
}

/* =========================================================
   Get Changed Files From GitHub Pull Request
   ========================================================= */

async function githubFiles(repoFullName, prNumber, token) {
  if (!token) {
    return [];
  }

  const url =
    `https://api.github.com/repos/${repoFullName}/pulls/${prNumber}/files?per_page=100`;

  const response = await fetch(url, {
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "AeroTrust"
    }
  });

  if (!response.ok) {
    throw new Error(
      `GitHub file API returned ${response.status}`
    );
  }

  const data = await response.json();

  return data.map(x => x.filename);
}

/* =========================================================
   Save Decision To Cloudflare D1
   ========================================================= */

async function saveDecision(env, data) {
  await env.DB.prepare(`
    INSERT INTO decisions
    (
      event_type,
      repository,
      pr_number,
      contributor,
      source_type,
      changed_files,
      decision,
      reason
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      data.event_type,
      data.repository,
      data.pr_number,
      data.contributor,
      data.source_type,
      JSON.stringify(data.changed_files || []),
      data.decision,
      data.reason
    )
    .run();
}

/* =========================================================
   GitHub Webhook Handler
   ========================================================= */

async function handleWebhook(request, env) {
  // Read the raw request body.
  // This is important because GitHub signs the exact raw body.
  const body = await request.text();

  // GitHub sends the HMAC signature in this header.
  const signature =
    request.headers.get("X-Hub-Signature-256");

  // Verify that the webhook really came from GitHub.
  const valid = await verifyGithubSignature(
    env.GITHUB_WEBHOOK_SECRET,
    body,
    signature
  );

  if (!valid) {
    return json(
      {
        error: "Invalid GitHub signature"
      },
      401
    );
  }

  // Identify the GitHub event.
  const event =
    request.headers.get("X-GitHub-Event");

  // AeroTrust only processes pull request events.
  if (event !== "pull_request") {
    return json({
      ok: true,
      ignored: event
    });
  }

  const payload = JSON.parse(body);

  // We only care about these PR actions.
  if (
    !["opened", "synchronize", "reopened"]
      .includes(payload.action)
  ) {
    return json({
      ok: true,
      ignored_action: payload.action
    });
  }

  const pr = payload.pull_request;

  const repo =
    payload.repository.full_name;

  // Ask GitHub which files were changed.
  const files = await githubFiles(
    repo,
    pr.number,
    env.GITHUB_TOKEN
  );

  // Determine whether the PR comes from a fork.
  const isFork =
    !!pr.head?.repo?.fork;

  // Run AeroTrust policy engine.
  const result = evaluatePolicy({
    isFork,
    contributor: pr.user?.login,
    files
  });

  // Store the decision in D1.
  await saveDecision(env, {
    event_type:
      `pull_request.${payload.action}`,

    repository: repo,

    pr_number: pr.number,

    contributor:
      pr.user?.login || "unknown",

    source_type:
      isFork
        ? "external_fork"
        : "same_repository",

    changed_files: files,

    decision: result.decision,

    reason: result.reason
  });

  // Send result back to GitHub.
  return json({
    ok: true,

    project: "AeroTrust",

    decision: result.decision,

    reason: result.reason,

    signals: result.signals,

    repository: repo,

    pull_request: pr.number
  });
}

/* =========================================================
   Dashboard
   ========================================================= */

async function dashboard(env) {
  const result = await env.DB.prepare(`
    SELECT *
    FROM decisions
    ORDER BY id DESC
    LIMIT 50
  `).all();

  return new Response(
    renderDashboard(result.results || []),
    {
      headers: {
        "content-type":
          "text/html; charset=utf-8"
      }
    }
  );
}

/* =========================================================
   Dashboard HTML
   ========================================================= */

function renderDashboard(rows) {
  const esc = s =>
    String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");

  const cards = rows
    .map(
      r => `
    <tr>
      <td>${esc(r.created_at)}</td>

      <td>${esc(r.repository)}</td>

      <td>#${esc(r.pr_number)}</td>

      <td>${esc(r.contributor)}</td>

      <td>${esc(r.source_type)}</td>

      <td>
        <strong class="${esc(
          r.decision
        ).toLowerCase()}">
          ${esc(r.decision)}
        </strong>
      </td>

      <td>${esc(r.reason)}</td>
    </tr>
  `
    )
    .join("");

  return `<!doctype html>

<html>

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>AeroTrust</title>

<style>

body {
  font-family: Inter, system-ui, sans-serif;
  background: #f5f8fc;
  color: #172033;
  margin: 0;
}

header {
  padding: 32px 7%;
  background: #eaf3ff;
  border-bottom: 1px solid #d8e4f2;
}

h1 {
  margin: 0 0 6px;
  font-size: 32px;
}

p {
  color: #536176;
}

main {
  padding: 28px 7%;
  overflow: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  background: white;
  border-radius: 14px;
  overflow: hidden;
}

th,
td {
  text-align: left;
  padding: 14px;
  border-bottom: 1px solid #edf0f4;
  font-size: 14px;
  vertical-align: top;
}

th {
  background: #f8fafc;
}

.allow {
  color: #16803c;
}

.review {
  color: #b06a00;
}

.block {
  color: #c62828;
}

</style>

</head>

<body>

<header>

<h1>AeroTrust</h1>

<p>
Zero Trust Security Gateway for GitHub Contributions
</p>

</header>

<main>

<h2>Policy Decisions</h2>

<table>

<thead>

<tr>

<th>Time</th>

<th>Repository</th>

<th>PR</th>

<th>Contributor</th>

<th>Source</th>

<th>Decision</th>

<th>Reason</th>

</tr>

</thead>

<tbody>

${
  cards ||
  "<tr><td colspan='7'>No decisions yet.</td></tr>"
}

</tbody>

</table>

</main>

</body>

</html>`;
}

/* =========================================================
   Main Cloudflare Worker
   ========================================================= */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    /* -----------------------------------------------------
       Dashboard
       ----------------------------------------------------- */

    if (
      request.method === "GET" &&
      url.pathname === "/"
    ) {
      return dashboard(env);
    }

    /* -----------------------------------------------------
       API: Get Decisions
       ----------------------------------------------------- */

    if (
      request.method === "GET" &&
      url.pathname === "/api/decisions"
    ) {
      const result =
        await env.DB.prepare(`
          SELECT *
          FROM decisions
          ORDER BY id DESC
          LIMIT 50
        `).all();

      return json(
        result.results || []
      );
    }

    /* -----------------------------------------------------
       GitHub Webhook
       ----------------------------------------------------- */

    if (
      request.method === "POST" &&
      url.pathname === "/webhook/github"
    ) {
      try {
        return await handleWebhook(
          request,
          env
        );
      } catch (error) {
        return json(
          {
            error: error.message
          },
          500
        );
      }
    }

    /* -----------------------------------------------------
       Manual Simulation
       ----------------------------------------------------- */

    if (
      request.method === "POST" &&
      url.pathname === "/simulate"
    ) {
      const input =
        await request.json();

      const result =
        evaluatePolicy({
          isFork: !!input.isFork,

          contributor:
            input.contributor ||
            "demo-user",

          files:
            input.files || []
        });

      await saveDecision(env, {
        event_type: "simulation",

        repository:
          input.repository ||
          "demo/example",

        pr_number:
          input.prNumber ||
          1,

        contributor:
          input.contributor ||
          "demo-user",

        source_type:
          input.isFork
            ? "external_fork"
            : "same_repository",

        changed_files:
          input.files || [],

        decision:
          result.decision,

        reason:
          result.reason
      });

      return json(result);
    }

    /* -----------------------------------------------------
       Unknown Route
       ----------------------------------------------------- */

    return json(
      {
        error: "Not found"
      },
      404
    );
  }
};