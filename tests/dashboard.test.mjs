import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { once } from "node:events";
import { createInterface } from "node:readline";
import test from "node:test";
import { JSDOM } from "jsdom";

const html = await readFile("src/recallguard/dashboard/index.html", "utf8");
const script = await readFile("src/recallguard/dashboard/dashboard.js", "utf8");
const reviewer = "r".repeat(32);
async function until(check, description) {
  for (let i = 0; i < 300; i++) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`Timed out: ${description}`);
}
async function app(t, semantic = false) {
  const server = spawn(
    process.env.PYTHON || "python",
    ["tests/dashboard_server.py", ...(semantic ? ["--semantic"] : [])],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let logs = "";
  server.stderr.on("data", (chunk) => {
    logs += chunk;
  });
  const lines = createInterface({ input: server.stdout });
  const [line] = await Promise.race([
    once(lines, "line"),
    once(server, "exit").then(() => {
      throw Error(logs || "Fixture service exited");
    }),
    new Promise((_, reject) => {
      const timer = setTimeout(
        () => reject(Error("Fixture startup timed out")),
        15000,
      );
      timer.unref();
    }),
  ]);
  const { url } = JSON.parse(line);
  t.after(async () => {
    lines.close();
    server.kill("SIGTERM");
    await once(server, "exit");
  });
  let ready = false;
  for (let i = 0; i < 200; i++) {
    try {
      ready = (await fetch(`${url}/health`)).ok;
    } catch {}
    if (ready) break;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.ok(ready, logs);
  const dom = new JSDOM(html, {
    url: `${url}/dashboard`,
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  t.after(() => dom.window.close());
  const { window: w } = dom,
    d = w.document;
  // jsdom does not implement native dialogs or rendering. Browser layout/focus is a separate check.
  w.HTMLDialogElement.prototype.showModal = function () {
    this.open = true;
  };
  w.HTMLDialogElement.prototype.close = function () {
    this.open = false;
  };
  w.AbortController = AbortController;
  const calls = [];
  w.fetch = async (path, options) => {
    calls.push({ path, options });
    return fetch(new URL(path, url), options);
  };
  w.eval(script);
  const q = (selector) => d.querySelector(selector);
  const click = (text, scope = d) => {
    const b = [...scope.querySelectorAll("button")].find(
      (b) => b.textContent.trim() === text,
    );
    assert.ok(b, `Missing button: ${text}`);
    b.click();
  };
  const connect = async (value = reviewer) => {
    q("#reviewer-key").value = value;
    q("#connect-form").requestSubmit();
    await until(() => !q("#connect-form button").disabled, "connection");
  };
  const state = async () =>
    (
      await fetch(`${url}/review`, { headers: { "X-API-Key": reviewer } })
    ).json();
  const navigate = async (page) => {
    q(`[data-page="${page}"]`).click();
    await new Promise((resolve) => setTimeout(resolve, 10));
  };
  const submitDecision = async () => {
    q("#field-reason").value = "Independently checked in this test";
    q("#action-content input[type=checkbox]").checked = true;
    q("#action-content form").requestSubmit();
    await until(
      () =>
        !q("#action-dialog").open || q("#action-content .error").textContent,
      "review action",
    );
    await until(() => !q("#close-action").disabled, "refresh after review");
  };
  return {
    w,
    d,
    q,
    click,
    connect,
    state,
    navigate,
    submitDecision,
    calls,
    url,
  };
}

test("unauthenticated shell has no records; agent credentials cannot open reviewer workspace", async (t) => {
  const a = await app(t);
  assert.equal(a.q("#workspace").hidden, true);
  assert.equal(a.q("#main").textContent, "");
  await a.connect("a".repeat(32));
  assert.equal(a.q("#workspace").hidden, true);
  assert.match(
    a.q("#connect-error").textContent,
    /Reviewer access was rejected/,
  );
  assert.equal(a.q("#reviewer-key").value, "");
  await a.connect();
  assert.equal(a.q("#workspace").hidden, false);
  assert.match(a.q("#main").textContent, /Security overview/);
  assert.equal(a.q("#memory-nav-count").textContent, "4");
  assert.equal(a.w.localStorage.length, 0);
  assert.equal(a.w.sessionStorage.length, 0);
  assert.ok(!a.d.body.textContent.includes(reviewer));
});

test("memory filtering and lineage navigation render hostile content as plain text", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("memories");
  const search = a.q('[aria-label="Search memories"]');
  search.value = "Ignore";
  search.dispatchEvent(new a.w.Event("input"));
  assert.equal(a.q("tbody").children.length, 1);
  a.click("Inspect");
  assert.match(a.q("#detail-content").textContent, /<img src=x onerror=/);
  assert.equal(a.q("#detail-content img"), null);
  assert.equal(a.w.pwned, undefined);
  assert.equal(
    [...a.q("#detail-content").querySelectorAll("button")].find(
      (b) => b.textContent === "Grant action scope",
    ).disabled,
    true,
  );
  a.q("#close-detail").click();
  search.value = "Summary";
  search.dispatchEvent(new a.w.Event("input"));
  a.click("Inspect");
  const parent = a.q(".lineage-col .lineage-node");
  assert.match(parent.textContent, /Northstar account is/);
  parent.click();
  assert.match(
    a.q("#detail-content .content-box").textContent,
    /^Northstar account is/,
  );
});

test("scoped grants require explicit confirmation and use server-advertised actions", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("memories");
  a.click("Shipment arrives on Thursday");
  a.click("Grant action scope");
  assert.deepEqual(
    [...a.q("#field-action").options].map((o) => o.value),
    ["payment", "change_bank", "send_message"],
  );
  a.q("#field-action").value = "change_bank";
  a.q("#field-target").value = "supplier:SHIP";
  a.q("#field-reason").value = "Independent verification";
  a.q("#action-content form").requestSubmit();
  assert.equal(a.calls.filter((c) => c.path === "/grants").length, 0);
  await a.submitDecision();
  const state = await a.state(),
    grant = state.grants.find((g) => g.target === "supplier:SHIP");
  assert.equal(grant.action, "change_bank");
  assert.equal(
    state.memories.find((m) => m.id === grant.memory_id).content,
    "Shipment arrives on Thursday",
  );
  assert.match(a.q("#notice").textContent, /Scoped grant issued/);
});

test("revocation form affects the selected memory and descendants, then updates the snapshot", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("memories");
  a.click("Northstar account is NS123456");
  a.click("Revoke memory & descendants");
  assert.match(a.q("#action-content").textContent, /1 descendants/);
  await a.submitDecision();
  const state = await a.state();
  assert.equal(state.memories.filter((m) => m.status === "revoked").length, 2);
  assert.ok(state.events.some((e) => e.kind === "lineage_revoked"));
  assert.match(a.q("#notice").textContent, /2 memories revoked/);
});

test("payment approval binds the displayed fingerprint and never executes a payment", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("payments");
  a.d.querySelector("tbody button.quiet:last-child").click(); // evidence link
  a.q("#close-detail").click();
  a.click("Review terms");
  a.click("Approve exact terms");
  const before = await a.state(),
    shownFingerprint = a.q("#action-content .mono").textContent;
  assert.ok(before.payments.some((p) => p.fingerprint === shownFingerprint));
  await a.submitDecision();
  const state = await a.state(),
    approved = state.payments.find((p) => p.status === "approved");
  assert.equal(approved.approved_fingerprint, shownFingerprint);
  assert.equal(state.receipts.length, 0);
  assert.ok(!a.calls.some((c) => c.path.endsWith("/execute")));
  assert.match(a.q("#notice").textContent, /No payment was executed/);
});

test("stale evidence causes approval rejection and leaves the proposal unapproved", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("payments");
  a.click("Review terms");
  a.click("Approve exact terms");
  const state = await a.state();
  await fetch(`${a.url}/memories/${state.payments[0].terms.memory_id}/revoke`, {
    method: "POST",
    headers: { "X-API-Key": reviewer, "Content-Type": "application/json" },
    body: JSON.stringify({ reason: "Revoked after snapshot" }),
  });
  await a.submitDecision();
  assert.match(
    a.q("#action-content .error").textContent,
    /Cannot approve payment/,
  );
  assert.ok(
    (await a.state()).payments.every((p) => p.status === "pending_review"),
  );
  assert.equal(a.q("#action-dialog").open, true);
});

test("payment cancellation is persisted without changing the invoice or executing it", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("payments");
  a.click("Review terms");
  a.click("Cancel proposal");
  await a.submitDecision();
  const state = await a.state();
  assert.equal(
    state.payments.filter((p) => p.status === "cancelled").length,
    1,
  );
  assert.ok(state.invoices.every((i) => i.status === "open"));
  assert.equal(state.receipts.length, 0);
});

test("retrieval form uses action/target scope and displays blocked reasons without blocked text", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("retrieval");
  a.q("#field-query").value = "Northstar";
  a.q("#field-retrieve-action").value = "payment";
  a.q("#field-retrieve-action").dispatchEvent(new a.w.Event("change"));
  a.q("#field-retrieve-target").value = "supplier:WRONG";
  a.q(".test-form").requestSubmit();
  await until(() => !a.q(".test-form button").disabled, "retrieval");
  const result = a.d.querySelectorAll(".grid .panel")[1];
  assert.match(result.textContent, /0 allowed/);
  assert.match(result.textContent, /scoped approval required/);
  assert.ok(!result.textContent.includes("NS123456"));
  assert.ok(
    (await a.state()).events.some((e) => e.kind === "retrieval_checked"),
  );
});

test("disconnect removes sensitive records and ignores a delayed response", async (t) => {
  const a = await app(t);
  await a.connect();
  let release;
  const stale = await a.state();
  a.w.fetch = () =>
    new Promise((resolve) => {
      release = () => resolve({ ok: true, json: async () => stale });
    });
  a.q("#refresh").click();
  a.q("#disconnect").click();
  release();
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(a.q("#main").textContent, "");
  assert.equal(a.q("#detail-content").textContent, "");
  assert.equal(a.q("#workspace").hidden, true);
  assert.equal(a.q("#reviewer-key").value, "");
});

test("audit search reads backend decisions and exposes full event details", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("activity");
  const search = a.q('[aria-label="Search audit events"]');
  search.value = "grant_issued";
  search.dispatchEvent(new a.w.Event("input"));
  assert.match(a.q("#main").textContent, /grant issued/);
  assert.match(a.q("#main pre").textContent, /supplier:NORTH/);
});

test("failed refresh retains the last snapshot and shows an actionable error", async (t) => {
  const a = await app(t);
  await a.connect();
  const old = a.q("#main").textContent;
  a.w.fetch = async () => {
    throw new a.w.TypeError("Network unavailable");
  };
  a.q("#refresh").click();
  await until(() => !a.q("#refresh").disabled, "failed refresh");
  assert.equal(a.q("#main").textContent, old);
  assert.match(a.q("#notice").textContent, /Refresh before retrying/);
});

test("embedding coverage and reviewer backfill use the configured model", async (t) => {
  const a = await app(t, true);
  await a.connect();
  assert.match(a.q("#main").textContent, /4 memories need indexing/);
  a.click("Index next 32 memories");
  await until(
    () => a.q("#notice").textContent.includes("Indexed 4 memories"),
    "backfill",
  );
  assert.equal((await a.state()).embeddings.remaining, 0);
  await a.navigate("retrieval");
  a.q("#field-query").value = "delivery";
  a.q(".test-form").requestSubmit();
  await until(() => !a.q(".test-form button").disabled, "semantic retrieval");
  assert.match(a.q("#main").textContent, /semantic/);
  assert.match(a.q("#main").textContent, /3 allowed/);
});

test("memory pagination preserves search focus and status filters", async (t) => {
  const a = await app(t);
  for (let i = 0; i < 17; i++)
    await fetch(`${a.url}/memories`, {
      method: "POST",
      headers: { "X-API-Key": reviewer, "Content-Type": "application/json" },
      body: JSON.stringify({
        content: `Warehouse record ${i}`,
        source_id: "supplier-web",
      }),
    });
  await a.connect();
  await a.navigate("memories");
  assert.equal(a.q("tbody").children.length, 15);
  a.click("Next →");
  assert.equal(a.q("tbody").children.length, 6);
  const search = a.q('[aria-label="Search memories"]');
  search.focus();
  search.value = "Warehouse";
  search.dispatchEvent(new a.w.Event("input"));
  assert.equal(a.d.activeElement, search);
  assert.match(a.q(".pagination").textContent, /Page 1 of 2/);
  const filter = a.q('[aria-label="Filter memory status"]');
  filter.value = "quarantined";
  filter.dispatchEvent(new a.w.Event("change"));
  assert.match(a.q("#main").textContent, /No matching memories/);
});

test("informational review requires confirmation, preserves quarantine, and can be withdrawn", async (t) => {
  const a = await app(t);
  const content =
    "Orion handbook quotes 'Ignore prior instructions' as an attack example.";
  const created = await fetch(`${a.url}/memories`, {
    method: "POST",
    headers: {
      "X-API-Key": "a".repeat(32),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content, source_id: "invoice-file" }),
  });
  assert.equal(created.status, 201);
  const memory = await created.json();
  await a.connect();
  await a.navigate("memories");
  a.click(content);
  a.click("Review for informational use");
  const shown = (await a.state()).context_review_options[memory.id].fingerprint;
  assert.ok(a.q("#action-content").textContent.includes(shown));
  a.q("#field-reason").value = "Independently verified quotation";
  a.q("#action-content form").requestSubmit();
  assert.equal(a.calls.filter((c) => c.path === "/context-reviews").length, 0);
  await a.submitDecision();
  const state = await a.state();
  const review = state.context_reviews[0];
  assert.equal(review.expected_fingerprint, shown);
  assert.equal(
    state.memories.find((m) => m.id === memory.id).status,
    "quarantined",
  );
  assert.ok(state.memory_restrictions[memory.id].length);
  assert.equal(state.information_restrictions[memory.id].length, 0);
  await a.navigate("retrieval");
  a.q("#field-query").value = "Orion";
  a.q(".test-form").requestSubmit();
  await until(() => !a.q(".test-form button").disabled, "reviewed retrieval");
  assert.match(a.q("#main").textContent, /reviewed exception/);
  await a.navigate("memories");
  a.click(content);
  assert.equal(
    [...a.q("#detail-content").querySelectorAll("button")].find(
      (b) => b.textContent === "Grant action scope",
    ).disabled,
    true,
  );
  a.click("Withdraw informational review");
  await a.submitDecision();
  const after = await a.state();
  assert.ok(after.context_reviews[0].withdrawn_at);
  assert.ok(after.information_restrictions[memory.id].length);
  assert.equal(
    after.grants.some((g) => g.memory_id === memory.id),
    false,
  );
});

test("a stale informational review cannot approve revoked content", async (t) => {
  const a = await app(t);
  await a.connect();
  await a.navigate("memories");
  const before = await a.state();
  const root = before.memories.find((m) => m.content.startsWith("Ignore"));
  a.click(root.content);
  a.click("Review for informational use");
  await fetch(`${a.url}/memories/${root.id}/revoke`, {
    method: "POST",
    headers: { "X-API-Key": reviewer, "Content-Type": "application/json" },
    body: JSON.stringify({ reason: "Revoked after snapshot" }),
  });
  await a.submitDecision();
  assert.match(a.q("#action-content .error").textContent, /not eligible/);
  assert.equal((await a.state()).context_reviews.length, 0);
});

test("independent claim verification enables only a separate evidence-bound grant and can be withdrawn", async (t) => {
  const a = await app(t);
  const headers = { "X-API-Key": reviewer, "Content-Type": "application/json" };
  const source = await fetch(`${a.url}/sources`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      id: "bank-record",
      kind: "user",
      locator: "fixture:independent-bank-record",
    }),
  });
  assert.equal(source.status, 201);
  const content = "Orion bank account is OR1234";
  const created = await fetch(`${a.url}/memories`, {
    method: "POST",
    headers: { ...headers, "X-API-Key": "a".repeat(32) },
    body: JSON.stringify({
      content,
      source_id: "invoice-file",
      claim: {
        entity: "supplier:Orion",
        attribute: "bank_account",
        value: "OR1234",
      },
    }),
  });
  assert.equal(created.status, 201);
  const memory = await created.json();
  await a.connect();
  await a.navigate("memories");
  a.click(content);
  assert.equal(
    [...a.q("#detail-content").querySelectorAll("button")].find(
      (b) => b.textContent === "Grant action scope",
    ).disabled,
    true,
  );
  a.click("Record independent verification");
  a.q("#field-evidence-source").value = "bank-record";
  a.q("#field-evidence-source").dispatchEvent(new a.w.Event("change"));
  assert.match(
    a.q("#action-content").textContent,
    /fixture:independent-bank-record/,
  );
  a.q("#field-evidence-reference").value = "callback-log:Orion-001";
  a.q("#field-method").value = "callback";
  a.q("#field-reason").value = "Confirmed with separate contact";
  a.q("#action-content form").requestSubmit();
  assert.equal(
    a.calls.filter((c) => c.path === "/claim-verifications").length,
    0,
  );
  await a.submitDecision();
  const verified = await a.state();
  const verification = verified.claim_verifications.find(
    (v) => v.memory_id === memory.id,
  );
  assert.equal(verification.evidence_source_id, "bank-record");
  assert.equal(
    verified.grants.some((g) => g.memory_id === memory.id),
    false,
  );
  a.click(content);
  a.click("Grant action scope");
  a.q("#field-action").value = "payment";
  a.q("#field-target").value = "supplier:Orion";
  await a.submitDecision();
  const granted = await a.state();
  assert.equal(
    granted.grants.find((g) => g.memory_id === memory.id).claim_verification_id,
    verification.id,
  );
  a.click(content);
  a.click("Withdraw claim verification");
  await a.submitDecision();
  const after = await a.state();
  assert.equal(after.claim_verification_options[memory.id].current_id, null);
  const retrieved = await fetch(`${a.url}/retrieve`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      query: "Orion",
      action: "payment",
      target: "supplier:Orion",
    }),
  });
  assert.equal((await retrieved.json()).allowed.length, 0);
});

test("conflict resolution previews all affected records and requires explicit independent confirmation", async (t) => {
  const a = await app(t);
  const headers = { "X-API-Key": reviewer, "Content-Type": "application/json" };
  const before = await a.state();
  const root = before.memories.find(
    (m) => m.content === "Northstar account is NS123456",
  );
  const other = await fetch(`${a.url}/memories`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      content: "Northstar account is NS999999",
      source_id: "invoice-file",
      claim: { ...root.claim, value: "NS999999" },
    }),
  });
  assert.equal(other.status, 201);
  const conflict = await other.json();
  await a.connect();
  await a.navigate("memories");
  a.click(root.content);
  a.click("Resolve using this claim");
  assert.match(
    a.q("#action-content").textContent,
    /3 records will remain or become revoked/,
  );
  assert.match(a.q("#action-content").textContent, /NS999999/);
  assert.match(
    a.q("#action-content").textContent,
    /Retirement cannot be undone/,
  );
  assert.ok(
    ![...a.q("#field-evidence-source").options].some(
      (o) => o.value === "invoice-file",
    ),
  );
  a.q("#field-evidence-reference").value = "Independent bank record 001";
  a.q("#field-reason").value = "Checked independent document";
  a.q("#action-content form").requestSubmit();
  assert.equal(
    a.calls.filter((c) => c.path === "/conflict-resolutions").length,
    0,
  );
  await a.submitDecision();
  assert.equal(a.q("#action-content .error").textContent, "");
  const after = await a.state();
  assert.equal(after.conflict_resolutions.length, 1);
  const resolution = after.conflict_resolutions[0];
  assert.ok(resolution.retired_memory_ids.includes(root.id));
  assert.ok(resolution.retired_memory_ids.includes(conflict.id));
  assert.ok(
    after.memories
      .filter((m) => resolution.retired_memory_ids.includes(m.id))
      .every((m) => m.status === "revoked"),
  );
  const replacement = after.memories.find(
    (m) => m.id === resolution.replacement_memory_id,
  );
  assert.equal(replacement.status, "active");
  assert.equal(
    after.claim_verification_options[replacement.id].current_id,
    null,
  );
  a.click(replacement.content);
  assert.match(
    a.q("#detail-content").textContent,
    /Conflict retired with a replacement/,
  );
  assert.equal(
    [...a.q("#detail-content").querySelectorAll("button")].find(
      (b) => b.textContent === "Grant action scope",
    ).disabled,
    true,
  );
});

test("conflict resolution rejects an impact change after opening the dialog", async (t) => {
  const a = await app(t);
  const headers = { "X-API-Key": reviewer, "Content-Type": "application/json" };
  const before = await a.state();
  const root = before.memories.find(
    (m) => m.content === "Northstar account is NS123456",
  );
  const write = async (data) => {
    const response = await fetch(`${a.url}/memories`, {
      method: "POST",
      headers,
      body: JSON.stringify(data),
    });
    assert.equal(response.status, 201);
  };
  await write({
    content: "Northstar alternate account",
    source_id: "invoice-file",
    claim: { ...root.claim, value: "NS999999" },
  });
  await a.connect();
  await a.navigate("memories");
  a.click(root.content);
  a.click("Resolve using this claim");
  a.q("#field-evidence-reference").value = "Independent bank record 002";
  await write({ content: "New derived observation", parent_ids: [root.id] });
  await a.submitDecision();
  assert.match(a.q("#action-content .error").textContent, /impact changed/);
  assert.equal((await a.state()).conflict_resolutions.length, 0);
});
