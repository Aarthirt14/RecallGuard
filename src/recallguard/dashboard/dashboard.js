// All record text is rendered with textContent. Never interpret memory content as HTML.
const $ = (selector) => document.querySelector(selector);
const pages = {
  overview: "Overview",
  memories: "Memories",
  payments: "Payment review",
  retrieval: "Retrieval lab",
  activity: "Audit log",
};
let key = "",
  snapshot = null,
  epoch = 0,
  busy = false;
let page = Object.hasOwn(pages, location.hash.slice(1))
  ? location.hash.slice(1)
  : "overview";
let memorySearch = "",
  memoryFilter = "all",
  memoryPage = 1,
  activitySearch = "",
  activityPage = 1;
const requests = new Set();
const short = (value) => String(value).slice(0, 8);
const human = (value) => String(value).replaceAll("_", " ");
const date = (value) =>
  value
    ? new Date(value).toLocaleString([], {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "—";
const el = (tag, className = "", text = null) => {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== null) n.textContent = text;
  return n;
};
const button = (text, handler, kind = "secondary") => {
  const n = el("button", kind, text);
  n.type = "button";
  n.addEventListener("click", handler);
  return n;
};
const badge = (text, color = "") => el("span", `badge ${color}`, human(text));
const statusBadge = (status) =>
  badge(
    status,
    {
      active: "green",
      quarantined: "amber",
      revoked: "red",
      pending_review: "amber",
      approved: "green",
      executed: "gray",
      cancelled: "red",
    }[status] || "gray",
  );
const empty = (title, text) => {
  const n = el("div", "empty");
  n.append(el("h3", "", title), el("p", "", text));
  return n;
};
const note = (text, warning = false) =>
  el("div", `callout${warning ? " warning" : ""}`, text);
const memoryById = (id) => snapshot.memories.find((m) => m.id === id);
const restrictions = (id) => snapshot.memory_restrictions[id] || [];
const supplierName = (id) =>
  snapshot.suppliers.find((s) => s.id === id)?.name || id;
const money = (terms) => {
  const formatter = new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: terms.currency,
  });
  const digits = formatter.resolvedOptions().maximumFractionDigits;
  return formatter.format(terms.amount_minor / 10 ** digits);
};
function notify(message, error = false) {
  $("#notice").textContent = message;
  $("#notice").className = `notice${error ? " error" : ""}`;
  $("#notice").hidden = false;
}
function clearPrivateView() {
  epoch += 1;
  key = "";
  snapshot = null;
  busy = false;
  for (const controller of requests) controller.abort();
  requests.clear();
  for (const dialog of document.querySelectorAll("dialog")) dialog.close();
  $("#main").replaceChildren();
  $("#detail-content").replaceChildren();
  $("#action-content").replaceChildren();
  $("#workspace").hidden = true;
  $("#connect-screen").hidden = false;
  $("#notice").hidden = true;
  $("#notice").textContent = "";
  $("#memory-nav-count").textContent = "";
  $("#payment-nav-count").textContent = "";
  $("#sync-label").textContent = "Disconnected";
  $("#reviewer-key").value = "";
  $("#connect-error").textContent = "";
  memorySearch = "";
  memoryFilter = "all";
  memoryPage = 1;
  activitySearch = "";
  activityPage = 1;
}
async function api(path, body, method = body === undefined ? "GET" : "POST") {
  const started = epoch;
  const controller = new AbortController();
  requests.add(controller);
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch(path, {
      method,
      headers: {
        "X-API-Key": key,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
      signal: controller.signal,
    });
    if (started !== epoch) throw new Error("Session ended.");
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error(
        "The service returned an unreadable response. Refresh before retrying.",
      );
    }
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        clearPrivateView();
        $("#connect-error").textContent =
          "Reviewer access was rejected. Check your reviewer key and reconnect.";
        throw new Error("Reviewer access was rejected.");
      }
      const detail =
        typeof data.detail === "string"
          ? data.detail
          : "The request was rejected. Check the entered values.";
      throw new Error(detail);
    }
    return data;
  } catch (error) {
    if (error.name === "AbortError" || error instanceof TypeError)
      throw new Error(
        "Connection interrupted. Refresh before retrying; your request may have completed.",
      );
    throw error;
  } finally {
    clearTimeout(timer);
    requests.delete(controller);
  }
}
async function refresh() {
  const started = epoch;
  const next = await api("/review");
  if (started !== epoch) return;
  snapshot = next;
  $("#sync-label").textContent = `Updated ${date(snapshot.captured_at)}`;
  $("#storage-label").textContent =
    snapshot.storage === "memory" ? "Ephemeral storage" : "Neo4j workspace";
  $("#memory-nav-count").textContent = snapshot.memories.length;
  $("#payment-nav-count").textContent =
    snapshot.payments.filter((p) => p.status === "pending_review").length || "";
  render();
}
async function refreshClick() {
  const b = $("#refresh");
  b.disabled = true;
  try {
    await refresh();
    notify("Workspace refreshed.");
  } catch (error) {
    if (key) notify(error.message, true);
  } finally {
    b.disabled = false;
  }
}
$("#connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = event.currentTarget.querySelector("button");
  submit.disabled = true;
  key = $("#reviewer-key").value.trim();
  $("#reviewer-key").value = "";
  $("#connect-error").textContent = "";
  try {
    await refresh();
    if (snapshot) {
      $("#connect-screen").hidden = true;
      $("#workspace").hidden = false;
      $("#main").focus();
    }
  } catch (error) {
    key = "";
    if (!$("#connect-error").textContent)
      $("#connect-error").textContent = error.message;
  } finally {
    submit.disabled = false;
  }
});
$("#disconnect").addEventListener("click", () => {
  clearPrivateView();
  $("#reviewer-key").focus();
});
$("#refresh").addEventListener("click", refreshClick);
// Do not retain credentials or records in a back/forward cache entry.
window.addEventListener("pagehide", clearPrivateView);
window.addEventListener("pageshow", (event) => {
  if (event.persisted) clearPrivateView();
});
for (const b of document.querySelectorAll("[data-page]"))
  b.addEventListener("click", () => navigate(b.dataset.page));
window.addEventListener("hashchange", () => {
  const next = location.hash.slice(1);
  if (Object.hasOwn(pages, next)) {
    page = next;
    if (snapshot) render();
  }
});
function navigate(next) {
  if (!Object.hasOwn(pages, next)) return;
  page = next;
  location.hash = next;
  render();
  $("#main").focus();
}
$("#close-detail").addEventListener("click", () => $("#detail-dialog").close());
$("#close-action").addEventListener("click", () => {
  if (!busy) $("#action-dialog").close();
});
$("#action-dialog").addEventListener("cancel", (event) => {
  if (busy) event.preventDefault();
});
function heading(title, description, tag) {
  const n = el("div", "page-heading"),
    text = el("div");
  text.append(
    el("p", "eyebrow", "RECALLGUARD / REVIEW WORKSPACE"),
    el("h1", "", title),
    el("p", "", description),
  );
  n.append(text);
  if (tag) n.append(badge(tag));
  return n;
}
function panel(title, action) {
  const n = el("section", "panel"),
    head = el("div", "panel-head");
  head.append(el("h2", "", title));
  if (action) head.append(action);
  n.append(head);
  return n;
}
function summary(label, value) {
  const n = el("div", "summary-line");
  n.append(el("span", "", label), el("strong", "", value));
  return n;
}
function fact(label, value, full = false, mono = false) {
  const n = el("div", `fact${full ? " full" : ""}`);
  n.append(
    el("span", "fact-label", label),
    el("span", mono ? "mono" : "", value),
  );
  return n;
}
function render() {
  if (!snapshot) return;
  $("#breadcrumb").textContent = pages[page];
  for (const b of document.querySelectorAll("[data-page]")) {
    if (b.dataset.page === page) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  $("#main").replaceChildren();
  ({
    overview: renderOverview,
    memories: renderMemories,
    payments: renderPayments,
    retrieval: renderRetrieval,
    activity: renderActivity,
  })[page]();
}
function renderOverview() {
  const main = $("#main");
  main.append(
    heading(
      "Security overview",
      "Trace memory origins, review restrictions, and keep action permissions in scope.",
      snapshot.retrieval_mode + " retrieval",
    ),
  );
  const restricted = snapshot.memories.filter(
    (m) => m.status !== "revoked" && restrictions(m.id).length,
  );
  const pending = snapshot.payments.filter(
    (p) => p.status === "pending_review",
  );
  const stats = el("div", "stats");
  for (const [label, value, caption] of [
    [
      "Total memories",
      snapshot.memories.length,
      `${snapshot.sources.length} registered sources`,
    ],
    ["Needs review", restricted.length, "Quarantine or restricted lineage"],
    [
      "Revoked",
      snapshot.memories.filter((m) => m.status === "revoked").length,
      "Excluded from agent context",
    ],
    ["Pending payments", pending.length, "Awaiting exact-term approval"],
  ]) {
    const n = el("div", "stat");
    n.append(
      el("span", "stat-label", label),
      el("strong", "stat-value", value),
      el("span", "stat-note", caption),
    );
    stats.append(n);
  }
  main.append(stats);
  const grid = el("div", "grid"),
    left = el("div", "stack"),
    right = el("div", "stack");
  const queue = panel(
    "Memories needing review",
    button("View memories →", () => navigate("memories"), "quiet"),
  );
  if (!restricted.length)
    queue.append(
      empty(
        "No memories awaiting review",
        "Quarantined records and memories with restricted ancestry will appear here.",
      ),
    );
  for (const m of restricted.slice(0, 4)) {
    const row = el("div", "list-row"),
      body = el("div");
    body.append(
      el("strong", "truncate", m.content),
      el("p", "", restrictions(m.id).map(human).join(" · ")),
    );
    row.append(
      el("span", "status-dot amber"),
      body,
      button("Inspect →", () => showMemory(m.id), "quiet"),
    );
    queue.append(row);
  }
  left.append(queue);
  const recent = panel(
    "Recent activity",
    button("Full audit log →", () => navigate("activity"), "quiet"),
  );
  if (!snapshot.events.length)
    recent.append(
      empty(
        "No activity recorded",
        "Memory writes, retrieval decisions, grants, and revocations are recorded automatically.",
      ),
    );
  for (const e of snapshot.events.slice(0, 5)) {
    const row = el("div", "list-row"),
      body = el("div");
    body.append(
      el("strong", "", human(e.kind)),
      el("p", "", `${e.actor} · ${date(e.created_at)}`),
    );
    row.append(
      el("span", "status-dot"),
      body,
      el("span", "mono muted", short(e.id)),
    );
    recent.append(row);
  }
  left.append(recent);
  const health = panel("Workspace boundaries"),
    body = el("div", "panel-body");
  body.append(
    summary("Storage", snapshot.storage === "memory" ? "Ephemeral" : "Neo4j"),
    summary("Retrieval", human(snapshot.retrieval_mode)),
    summary("Registered sources", snapshot.sources.length),
    summary("Recorded audit events", snapshot.event_count),
    note(
      "Active memory is eligible for review. It does not automatically authorize an action.",
    ),
  );
  if (snapshot.storage === "memory")
    body.append(
      note("This workspace loses its records when the service restarts.", true),
    );
  health.append(body);
  right.append(health);
  const embeddings = panel("Embedding coverage"),
    eb = el("div", "panel-body");
  if (snapshot.embeddings.enabled) {
    eb.append(
      summary(
        "Indexed nonrevoked memories",
        `${snapshot.embeddings.indexed} / ${snapshot.embeddings.eligible}`,
      ),
    );
    const progress = el("progress");
    progress.max = snapshot.embeddings.eligible || 1;
    progress.value = snapshot.embeddings.indexed;
    progress.setAttribute("aria-label", "Embedding coverage");
    eb.append(progress);
    eb.append(
      el(
        "p",
        "muted",
        `${snapshot.embeddings.remaining} memories need indexing for the current model.`,
      ),
    );
    const b = button("Index next 32 memories", async () => {
      b.disabled = true;
      try {
        const result = await api("/embeddings/reindex", { limit: 32 });
        await refresh();
        notify(
          `Indexed ${result.indexed} memories. ${result.remaining} remain.`,
        );
      } catch (error) {
        if (key) notify(error.message, true);
      } finally {
        b.disabled = false;
      }
    });
    b.disabled = snapshot.embeddings.remaining === 0;
    eb.append(b);
  } else
    eb.append(
      el(
        "p",
        "muted",
        "Lexical search is enabled. Local embeddings are not configured for this service.",
      ),
      button("Test retrieval →", () => navigate("retrieval"), "quiet"),
    );
  embeddings.append(eb);
  right.append(embeddings);
  grid.append(left, right);
  main.append(grid);
}
function table(headers) {
  const wrap = el("div", "table-wrap"),
    t = el("table"),
    head = el("thead"),
    row = el("tr"),
    body = el("tbody");
  for (const label of headers) {
    const th = el("th", "", label);
    th.scope = "col";
    row.append(th);
  }
  head.append(row);
  t.append(head, body);
  wrap.append(t);
  return { wrap, body };
}
function pagination(total, current, size, onChange) {
  const pages = Math.max(1, Math.ceil(total / size)),
    n = el("div", "pagination"),
    controls = el("div");
  n.append(el("span", "", `Page ${current} of ${pages} · ${total} records`));
  const prev = button("← Previous", () => onChange(current - 1)),
    next = button("Next →", () => onChange(current + 1));
  prev.disabled = current <= 1;
  next.disabled = current >= pages;
  controls.append(prev, next);
  n.append(controls);
  return n;
}
function renderMemories() {
  const main = $("#main");
  main.append(
    heading(
      "Memory explorer",
      "Inspect the content, origins, and restrictions behind every record.",
    ),
  );
  const toolbar = el("div", "toolbar"),
    search = el("input"),
    filter = el("select"),
    host = el("div", "panel");
  search.type = "search";
  search.placeholder = "Search content, source, or memory ID";
  search.setAttribute("aria-label", "Search memories");
  search.value = memorySearch;
  filter.setAttribute("aria-label", "Filter memory status");
  for (const [value, label] of [
    ["all", "All statuses"],
    ["restricted", "Needs review"],
    ["active", "Active"],
    ["quarantined", "Quarantined"],
    ["revoked", "Revoked"],
  ]) {
    const o = el("option", "", label);
    o.value = value;
    filter.append(o);
  }
  filter.value = memoryFilter;
  const count = el("span", "count");
  toolbar.append(search, filter, count);
  main.append(toolbar, host);
  const update = () => {
    const q = memorySearch.toLocaleLowerCase();
    const records = snapshot.memories.filter(
      (m) =>
        `${m.content} ${m.id} ${m.origin_ids.join(" ")}`
          .toLocaleLowerCase()
          .includes(q) &&
        (memoryFilter === "all" ||
          (memoryFilter === "restricted"
            ? m.status !== "revoked" && restrictions(m.id).length
            : m.status === memoryFilter)),
    );
    memoryPage = Math.min(
      memoryPage,
      Math.max(1, Math.ceil(records.length / 15)),
    );
    count.textContent = `${records.length} of ${snapshot.memories.length} memories`;
    host.replaceChildren();
    if (!records.length) {
      host.append(
        empty(
          snapshot.memories.length
            ? "No matching memories"
            : "Your memory store is empty",
          snapshot.memories.length
            ? "Try another phrase or status filter."
            : "Ingest a source observation through the API or agent workflow to begin.",
        ),
      );
      return;
    }
    const t = table(["MEMORY", "STATUS", "ORIGIN", "AUTHORITY", ""]);
    for (const m of records.slice((memoryPage - 1) * 15, memoryPage * 15)) {
      const row = el("tr"),
        content = el("td"),
        state = el("td"),
        origin = el("td"),
        authority = el("td"),
        inspect = el("td");
      content.append(
        button(m.content, () => showMemory(m.id), "content-link"),
        el("small", "mono", short(m.id) + " · " + date(m.created_at)),
      );
      state.append(statusBadge(m.status));
      if (m.status === "active" && restrictions(m.id).length)
        state.append(el("small", "", "Restricted ancestry"));
      origin.append(
        el("span", "", m.origin_ids.join(", ")),
        el(
          "small",
          "",
          m.parent_ids.length
            ? `${m.parent_ids.length} parent memories`
            : "Direct source",
        ),
      );
      authority.append(el("span", "mono", `${m.authority} / 5`));
      inspect.append(button("Inspect", () => showMemory(m.id), "quiet"));
      row.append(content, state, origin, authority, inspect);
      t.body.append(row);
    }
    host.append(
      t.wrap,
      pagination(records.length, memoryPage, 15, (value) => {
        memoryPage = value;
        update();
      }),
    );
  };
  search.addEventListener("input", () => {
    memorySearch = search.value;
    memoryPage = 1;
    update();
  });
  filter.addEventListener("change", () => {
    memoryFilter = filter.value;
    memoryPage = 1;
    update();
  });
  update();
}
function descendants(id) {
  const found = new Set([id]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const m of snapshot.memories)
      if (!found.has(m.id) && m.parent_ids.some((p) => found.has(p))) {
        found.add(m.id);
        changed = true;
      }
  }
  found.delete(id);
  return [...found];
}
function lineage(memory) {
  const n = el("div", "lineage");
  const column = (label) => {
    const c = el("div", "lineage-col");
    c.append(el("small", "", label));
    return c;
  };
  const parents = column(memory.parent_ids.length ? "PARENTS" : "SOURCE"),
    selected = column("THIS MEMORY"),
    children = column("DIRECT DESCENDANTS");
  if (memory.parent_ids.length)
    for (const id of memory.parent_ids)
      parents.append(
        button(
          `${short(id)} · ${memoryById(id)?.content.slice(0, 50) || "Memory"}`,
          () => showMemory(id),
          "lineage-node",
        ),
      );
  else {
    const source = snapshot.sources.find((s) => s.id === memory.source_id);
    parents.append(
      el(
        "div",
        "lineage-node",
        `${source?.id || memory.source_id} · ${source?.kind || ""}`,
      ),
    );
  }
  selected.append(
    el(
      "div",
      "lineage-node selected",
      `${short(memory.id)} · ${human(memory.status)}`,
    ),
  );
  const direct = snapshot.memories.filter((m) =>
    m.parent_ids.includes(memory.id),
  );
  for (const m of direct.slice(0, 8))
    children.append(
      button(
        `${short(m.id)} · ${m.content.slice(0, 50)}`,
        () => showMemory(m.id),
        "lineage-node",
      ),
    );
  if (!direct.length)
    children.append(el("div", "lineage-node", "No derived memories"));
  if (direct.length > 8)
    children.append(
      el("small", "", `Showing 8 of ${direct.length} direct descendants`),
    );
  n.append(
    parents,
    el("span", "lineage-arrow", "→"),
    selected,
    el("span", "lineage-arrow", "→"),
    children,
  );
  return n;
}
function showMemory(id) {
  const m = memoryById(id);
  if (!m) {
    notify("Memory is not in this snapshot. Refresh the workspace.", true);
    return;
  }
  const content = $("#detail-content");
  content.replaceChildren();
  $("#detail-kind").textContent = "MEMORY RECORD";
  const title = el("h2", "", "Memory inspection");
  title.id = "detail-title";
  content.append(title, el("p", "mono muted", m.id));
  const tags = el("div", "tag-list");
  tags.append(statusBadge(m.status), badge(m.memory_type));
  for (const taint of m.taint_labels) tags.append(badge(taint, "amber"));
  content.append(tags, el("div", "content-box", m.content));
  const facts = el("div", "facts");
  facts.append(
    fact(
      "Origin authority ceiling",
      `${m.authority} / 5 · Not a confidence score`,
    ),
    fact("Recorded", date(m.created_at)),
    fact("Origin sources", m.origin_ids.join(", ")),
    fact("Derived descendants", String(descendants(id).length)),
    fact("Content hash", m.content_hash, true, true),
  );
  content.append(facts);
  if (m.claim)
    content.append(
      note(
        `Structured claim: ${m.claim.entity} / ${m.claim.attribute} = ${m.claim.value}`,
      ),
    );
  if (restrictions(id).length)
    content.append(
      note(
        `Restricted: ${restrictions(id).map(human).join("; ")}. Action grants cannot override these restrictions.`,
        true,
      ),
    );
  else
    content.append(
      note(
        "No lifecycle restrictions in this snapshot. Consequential use still requires an exact action and target grant.",
      ),
    );
  if (m.conflict_ids.length) {
    const conflicts = el("div", "tag-list spaced");
    conflicts.append(el("span", "muted", "Conflicts:"));
    for (const cid of m.conflict_ids)
      conflicts.append(button(short(cid), () => showMemory(cid), "quiet"));
    content.append(conflicts);
  }
  content.append(
    el("h3", "section-title", "Lineage"),
    lineage(m),
    el(
      "p",
      "field-note",
      "Select a parent or descendant to follow its lineage. Revoking a memory restricts every descendant, including indirect derivations.",
    ),
  );
  const sources = el("details", "event-details");
  sources.append(el("summary", "", "Registered source details"));
  const sourceList = el("div", "facts");
  for (const origin of m.origin_ids) {
    const source = snapshot.sources.find((s) => s.id === origin);
    if (source)
      sourceList.append(fact(`${source.id} · ${source.kind}`, source.locator));
  }
  sources.append(sourceList);
  content.append(sources);
  showConflictResolution(m, content);
  if (m.claim) showClaimVerification(m, content);
  content.append(el("h3", "section-title", "Informational review"));
  const option = snapshot.context_review_options[id];
  content.append(
    note(
      "A reviewer may permit an overblocked direct-source record in informational retrieval only. This does not verify its claims, release quarantine, authorize tools, or permit derived summaries.",
    ),
  );
  const reviewButton = button("Review for informational use", () =>
    reviewInformation(m, option),
  );
  reviewButton.disabled =
    option.blockers.length > 0 || Boolean(option.effective_review_id);
  content.append(reviewButton);
  if (option.blockers.length)
    content.append(
      el(
        "p",
        "field-note",
        `Unavailable: ${option.blockers.map(human).join("; ")}.`,
      ),
    );
  for (const r of snapshot.context_reviews.filter((r) => r.memory_id === id)) {
    const row = el("div", "list-row"),
      body = el("div");
    const state = r.withdrawn_at
      ? "withdrawn"
      : new Date(r.expires_at) <= new Date(snapshot.captured_at)
        ? "expired"
        : option.effective_review_id === r.id
          ? "effective for information"
          : "invalidated";
    body.append(
      el("strong", "", human(state)),
      el(
        "p",
        "",
        `${r.reviewed_by} · Expires ${date(r.expires_at)} · ${r.reason}`,
      ),
    );
    if (r.withdrawn_at)
      body.append(
        el(
          "p",
          "muted",
          `Withdrawn ${date(r.withdrawn_at)} · ${r.withdrawal_reason}`,
        ),
      );
    row.append(body);
    if (!r.withdrawn_at)
      row.append(
        button(
          "Withdraw informational review",
          () => withdrawInformation(r),
          "danger",
        ),
      );
    content.append(row);
  }
  content.append(el("h3", "section-title", "Action grants"));
  const grants = snapshot.grants.filter((g) => g.memory_id === id);
  if (!grants.length)
    content.append(
      el("p", "muted", "No action grants have been issued for this memory."),
    );
  for (const g of grants) {
    const row = el("div", "list-row"),
      text = el("div");
    text.append(
      el("strong", "", `${human(g.action)} → ${g.target}`),
      el("p", "", `Expires ${date(g.expires_at)} · ${g.reason}`),
    );
    if (m.claim)
      text.append(
        el(
          "small",
          "mono",
          `Evidence verification: ${g.claim_verification_id || "missing"}`,
        ),
      );
    const evidenceInvalid =
      m.claim &&
      (!g.claim_verification_id ||
        g.claim_verification_id !==
          snapshot.claim_verification_options[id].current_id);
    row.append(
      text,
      badge(
        new Date(g.expires_at) <= new Date(snapshot.captured_at)
          ? "expired"
          : restrictions(id).length || evidenceInvalid
            ? "restricted"
            : "unexpired",
        restrictions(id).length || evidenceInvalid ? "amber" : "gray",
      ),
    );
    content.append(row);
  }
  const actions = el("div", "form-actions"),
    grant = button("Grant action scope", () => grantMemory(m), "primary"),
    revoke = button(
      "Revoke memory & descendants",
      () => revokeMemory(m),
      "danger",
    );
  grant.disabled =
    restrictions(id).length > 0 ||
    Boolean(m.claim && !snapshot.claim_verification_options[id].current_id);
  revoke.disabled = m.status === "revoked";
  actions.append(grant, revoke);
  content.append(actions);
  if (!$("#detail-dialog").open) $("#detail-dialog").showModal();
}
function field(label, name, type = "text", value = "") {
  const wrap = el("div"),
    id = `field-${name}`,
    input = el(type === "textarea" ? "textarea" : "input");
  input.id = id;
  input.name = name;
  if (type !== "textarea") input.type = type;
  input.value = value;
  input.required = true;
  const l = el("label", "", label);
  l.htmlFor = id;
  wrap.append(l, input);
  return { wrap, input };
}
function selectField(label, name, options) {
  const wrap = el("div"),
    input = el("select");
  input.id = `field-${name}`;
  input.name = name;
  for (const [value, label] of options) {
    const o = el("option", "", label);
    o.value = value;
    input.append(o);
  }
  const l = el("label", "", label);
  l.htmlFor = input.id;
  wrap.append(l, input);
  return { wrap, input };
}
function decisionDialog(
  titleText,
  description,
  submitLabel,
  build,
  perform,
  danger = false,
) {
  const content = $("#action-content");
  content.replaceChildren();
  const title = el("h2", "", titleText);
  title.id = "action-title";
  content.append(title, el("p", "muted", description));
  const form = el("form"),
    grid = el("div", "form-grid");
  form.append(grid);
  build(grid);
  const reason = field("Review reason", "reason", "textarea");
  reason.input.minLength = 5;
  reason.input.maxLength = 2000;
  reason.wrap.className = "full";
  grid.append(reason.wrap);
  const check = el("label", "checkbox-label full"),
    checkbox = el("input");
  checkbox.type = "checkbox";
  checkbox.required = true;
  check.append(
    checkbox,
    el(
      "span",
      "",
      danger
        ? "I understand the affected records and confirm this restriction."
        : "I independently verified the evidence and the exact scope shown above.",
    ),
  );
  grid.append(check);
  const error = el("p", "error");
  error.setAttribute("role", "alert");
  const actions = el("div", "form-actions"),
    cancel = button("Cancel", () => $("#action-dialog").close()),
    submit = el("button", danger ? "danger" : "primary", submitLabel);
  submit.type = "submit";
  actions.append(cancel, submit);
  form.append(error, actions);
  content.append(form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    submit.disabled = true;
    cancel.disabled = true;
    $("#close-action").disabled = true;
    error.textContent = "";
    const started = epoch;
    try {
      const message = await perform(new FormData(form));
      if (started !== epoch) return;
      $("#action-dialog").close();
      $("#detail-dialog").close();
      try {
        await refresh();
        notify(message);
      } catch (refreshError) {
        if (key)
          notify(`${message} Refresh failed: ${refreshError.message}`, true);
      }
    } catch (failure) {
      if (started === epoch) error.textContent = failure.message;
    } finally {
      busy = false;
      submit.disabled = false;
      cancel.disabled = false;
      $("#close-action").disabled = false;
    }
  });
  $("#action-dialog").showModal();
}
function expiryFields(grid) {
  const f = field("Expires in (minutes)", "minutes", "number", "60");
  f.input.min = "1";
  f.input.max = "1440";
  f.input.step = "1";
  grid.append(f.wrap);
}
const expiry = (data) =>
  new Date(Date.now() + Number(data.get("minutes")) * 60000).toISOString();
function grantMemory(m) {
  decisionDialog(
    "Grant action scope",
    "Permit this exact memory to influence one action and target. This does not approve a payment transaction.",
    "Issue scoped grant",
    (grid) => {
      const record = note(`Memory ${m.id}\nContent hash: ${m.content_hash}`);
      record.classList.add("full");
      grid.append(record);
      const action = selectField(
        "Action",
        "action",
        snapshot.actions
          .filter((a) => a !== "inform")
          .map((a) => [a, human(a)]),
      );
      const target = field("Exact target", "target");
      target.input.maxLength = 200;
      target.input.placeholder = "supplier:ABC";
      grid.append(action.wrap, target.wrap);
      expiryFields(grid);
    },
    async (data) => {
      await api("/grants", {
        memory_id: m.id,
        action: data.get("action"),
        target: data.get("target").trim(),
        reason: data.get("reason").trim(),
        expires_at: expiry(data),
      });
      return "Scoped grant issued. Descendants do not inherit this approval.";
    },
  );
}
function showConflictResolution(m, content) {
  const option = snapshot.conflict_resolution_options[m.id];
  const history = snapshot.conflict_resolutions.filter(
    (r) =>
      r.retired_memory_ids.includes(m.id) || r.replacement_memory_id === m.id,
  );
  if (!option?.conflicting_memory_ids.length && !history.length) return;
  content.append(el("h3", "section-title", "Conflict resolution"));
  if (option?.conflicting_memory_ids.length) {
    content.append(
      note(
        "Independently check this claim before selecting it. Resolution permanently retires all records for this claim key and their descendants, and creates a fresh assertion from the separate source. Old permissions stay blocked.",
        true,
      ),
    );
    const resolve = button("Resolve using this claim", () =>
      resolveConflict(m, option),
    );
    resolve.disabled = !option.evidence_sources.length;
    content.append(resolve);
    if (!option.evidence_sources.length)
      content.append(
        note(
          "No eligible separate source, or the replacement claim is restricted. Register independent evidence through the sources API first.",
        ),
      );
  }
  for (const r of history) {
    const row = el("div", "list-row"),
      body = el("div");
    body.append(
      el("strong", "", "Conflict retired with a replacement"),
      el("p", "", `${r.resolved_by} · ${date(r.created_at)} · ${r.reason}`),
      el(
        "p",
        "",
        `${r.evidence_source_id} · ${human(r.method)} · ${r.evidence_reference}`,
      ),
      el(
        "p",
        "",
        `${r.retired_memory_ids.length} records retired. This is a historical decision, not a current action permission.`,
      ),
    );
    row.append(
      body,
      button(
        "Inspect replacement",
        () => showMemory(r.replacement_memory_id),
        "quiet",
      ),
    );
    content.append(row);
  }
}
function resolveConflict(m, option) {
  decisionDialog(
    "Resolve conflicting claims",
    "Complete the independent check outside this app. Retirement cannot be undone. The replacement needs a separate verification and grant before consequential use. In semantic workspaces, run embedding backfill to index it.",
    "Retire conflicts and create replacement",
    (grid) => {
      const impact = note(
        `Selected replacement: ${option.replacement_content}\n${option.conflicting_memory_ids.length} records share this claim key. ${option.retired_memory_ids.length} records will remain or become revoked, including descendants.`,
        true,
      );
      impact.classList.add("full");
      grid.append(impact);
      const affected = el("details", "full event-details");
      affected.append(el("summary", "", "Inspect every affected record"));
      for (const id of option.retired_memory_ids) {
        const record = memoryById(id);
        affected.append(
          el("p", "", `${id} · ${record.status} · ${record.content}`),
        );
      }
      grid.append(affected);
      const source = selectField(
        "Separate evidence source",
        "evidence-source",
        option.evidence_sources.map((s) => [s.id, s.id]),
      );
      const method = selectField("Checking method", "method", [
        ["official_record", "Official record"],
        ["callback", "Independent callback"],
        ["in_person", "In-person check"],
      ]);
      const reference = field(
        "Document, page or callback log reference",
        "evidence-reference",
      );
      reference.input.minLength = 5;
      reference.input.maxLength = 2000;
      const details = note("");
      details.classList.add("full");
      const updateSource = () => {
        const registered = snapshot.sources.find(
          (s) => s.id === source.input.value,
        );
        details.textContent = `${registered.id} · ${registered.kind}\n${registered.locator}`;
      };
      source.input.addEventListener("change", updateSource);
      updateSource();
      grid.append(source.wrap, method.wrap, reference.wrap, details);
    },
    async (data) => {
      const source = option.evidence_sources.find(
        (s) => s.id === data.get("evidence-source"),
      );
      await api("/conflict-resolutions", {
        selected_memory_id: m.id,
        evidence_source_id: source.id,
        expected_fingerprint: source.fingerprint,
        evidence_reference: data.get("evidence-reference").trim(),
        method: data.get("method"),
        independently_checked: true,
        reason: data.get("reason").trim(),
      });
      return "Conflicting records retired. Inspect the replacement for fresh verification and permissions.";
    },
  );
}
function showClaimVerification(m, content) {
  const options = snapshot.claim_verification_options[m.id];
  content.append(el("h3", "section-title", "Claim verification"));
  content.append(
    note(
      "Record an independent check before granting action scope. A matching source label alone does not prove the claim or the source's independence.",
    ),
  );
  const verify = button("Record independent verification", () =>
    verifyClaim(m, options),
  );
  verify.disabled =
    !options.evidence_sources.length || Boolean(options.current_id);
  content.append(verify);
  if (!options.evidence_sources.length)
    content.append(
      el(
        "p",
        "field-note",
        "No eligible evidence source. The claim must be unrestricted and a separate source must be registered.",
      ),
    );
  for (const v of snapshot.claim_verifications.filter(
    (v) => v.memory_id === m.id,
  )) {
    const row = el("div", "list-row"),
      body = el("div");
    const status = v.withdrawn_at
      ? "withdrawn"
      : new Date(v.expires_at) <= new Date(snapshot.captured_at)
        ? "expired"
        : v.id === options.current_id
          ? "current reviewer check"
          : "invalidated";
    body.append(
      el("strong", "", human(status)),
      el(
        "p",
        "",
        `${v.evidence_source_id} · ${human(v.method)} · ${v.evidence_reference}`,
      ),
      el(
        "p",
        "",
        `${v.verified_by} · Expires ${date(v.expires_at)} · ${v.reason}`,
      ),
    );
    if (v.withdrawn_at)
      body.append(el("p", "muted", `Withdrawn: ${v.withdrawal_reason}`));
    row.append(body);
    if (!v.withdrawn_at)
      row.append(
        button(
          "Withdraw claim verification",
          () => withdrawVerification(v),
          "danger",
        ),
      );
    content.append(row);
  }
}
function verifyClaim(m, options) {
  decisionDialog(
    "Record independent claim verification",
    "Complete the check outside this app first. The app records your evidence and enforces its scope; it does not contact the source or confirm the claim itself.",
    "Record verification",
    (grid) => {
      const claim = note(
        `${m.claim.entity} / ${m.claim.attribute} = ${m.claim.value}`,
      );
      claim.classList.add("full");
      grid.append(claim);
      const source = selectField(
        "Separate evidence source",
        "evidence-source",
        options.evidence_sources.map((s) => [s.id, s.id]),
      );
      const method = selectField("Checking method", "method", [
        ["official_record", "Official record"],
        ["callback", "Independent callback"],
        ["in_person", "In-person check"],
      ]);
      const reference = field(
        "Document, page or callback log reference",
        "evidence-reference",
      );
      reference.input.minLength = 5;
      reference.input.maxLength = 2000;
      const details = note("");
      details.classList.add("full");
      const updateSource = () => {
        const selected = options.evidence_sources.find(
          (s) => s.id === source.input.value,
        );
        const registered = snapshot.sources.find((s) => s.id === selected.id);
        details.textContent = `${registered.id} · ${registered.kind}\n${registered.locator}\nFingerprint: ${selected.fingerprint}`;
      };
      source.input.addEventListener("change", updateSource);
      updateSource();
      grid.append(source.wrap, method.wrap, reference.wrap, details);
      expiryFields(grid);
    },
    async (data) => {
      const source = options.evidence_sources.find(
        (s) => s.id === data.get("evidence-source"),
      );
      await api("/claim-verifications", {
        memory_id: m.id,
        evidence_source_id: source.id,
        expected_fingerprint: source.fingerprint,
        evidence_reference: data.get("evidence-reference").trim(),
        method: data.get("method"),
        independently_checked: true,
        reason: data.get("reason").trim(),
        expires_at: expiry(data),
      });
      return "Independent check recorded. Issue a separate action grant to authorize use.";
    },
  );
}
function withdrawVerification(v) {
  decisionDialog(
    "Withdraw claim verification",
    "Dependent grants and pending payments will fail their next evidence check. Completed actions remain in the audit history.",
    "Confirm evidence withdrawal",
    (grid) =>
      grid.append(
        note(
          `Verification ${v.id} · Memory ${v.memory_id} · ${v.evidence_reference}`,
        ),
      ),
    async (data) => {
      await api(`/claim-verifications/${encodeURIComponent(v.id)}/withdraw`, {
        reason: data.get("reason").trim(),
      });
      return "Verification withdrawn. Dependent permissions require new evidence and new approvals.";
    },
    true,
  );
}
function reviewInformation(m, option) {
  decisionDialog(
    "Review informational context",
    "Confirm that this exact text was overblocked. Other records and derived summaries remain restricted. The exception expires and can be withdrawn.",
    "Approve informational use",
    (grid) => {
      const text = el("div", "content-box full", m.content);
      grid.append(text);
      if (m.claim)
        grid.append(
          note(
            `Claim: ${m.claim.entity} / ${m.claim.attribute} = ${m.claim.value}`,
          ),
        );
      const record = note(
        `Memory ${m.id}\nReview fingerprint: ${option.fingerprint}`,
      );
      record.classList.add("full");
      grid.append(record);
      expiryFields(grid);
    },
    async (data) => {
      await api("/context-reviews", {
        memory_id: m.id,
        expected_fingerprint: option.fingerprint,
        reason: data.get("reason").trim(),
        expires_at: expiry(data),
      });
      return "Informational review recorded. Quarantine and tool restrictions remain in place.";
    },
  );
}
function withdrawInformation(review) {
  decisionDialog(
    "Withdraw informational review",
    "Stop using this exception for subsequent retrieval. Text already returned cannot be recalled.",
    "Confirm withdrawal",
    (grid) =>
      grid.append(note(`Review ${review.id} for memory ${review.memory_id}`)),
    async (data) => {
      await api(`/context-reviews/${encodeURIComponent(review.id)}/withdraw`, {
        reason: data.get("reason").trim(),
      });
      return "Informational review withdrawn. Future retrieval uses the current restrictions.";
    },
    true,
  );
}
function revokeMemory(m) {
  decisionDialog(
    "Revoke memory lineage",
    "The memory and all descendants will be excluded from retrieval. Records remain available for audit; there is no restore action.",
    "Confirm revocation",
    (grid) => {
      const n = note(
        `Memory ${m.id}. This snapshot contains ${descendants(m.id).length} descendants. The server also revokes descendants added since this snapshot.`,
        true,
      );
      n.classList.add("full");
      grid.append(n);
    },
    async (data) => {
      const result = await api(`/memories/${encodeURIComponent(m.id)}/revoke`, {
        reason: data.get("reason").trim(),
      });
      return `${result.revoked_ids.length} memories revoked. Existing grants can no longer authorize their use.`;
    },
    true,
  );
}
function renderPayments() {
  const main = $("#main");
  main.append(
    heading(
      "Payment review",
      "Review exact terms and evidence before authorizing a simulated transaction.",
      "Simulation only",
    ),
  );
  const host = el("div", "panel");
  main.append(host);
  if (!snapshot.payments.length) {
    host.append(
      empty(
        "No payment proposals",
        "Proposals appear after the procurement workflow finds eligible account evidence for a registered invoice.",
      ),
    );
    return;
  }
  const t = table(["INVOICE / SUPPLIER", "AMOUNT", "STATUS", "EVIDENCE", ""]);
  for (const p of snapshot.payments) {
    const row = el("tr"),
      invoice = el("td"),
      amount = el("td"),
      state = el("td"),
      evidence = el("td"),
      inspect = el("td");
    invoice.append(
      el("strong", "", p.terms.invoice_id),
      el("small", "", supplierName(p.terms.supplier_id)),
    );
    amount.append(el("span", "mono", money(p.terms)));
    state.append(statusBadge(p.status));
    if (
      p.status === "approved" &&
      new Date(p.approval_expires_at) <= new Date(snapshot.captured_at)
    )
      state.append(el("small", "", "Approval expired"));
    if (
      ["pending_review", "approved"].includes(p.status) &&
      snapshot.payment_blockers[p.id]?.length
    )
      state.append(el("small", "", "Current evidence is blocked"));
    evidence.append(
      button(
        short(p.terms.memory_id),
        () => showMemory(p.terms.memory_id),
        "quiet",
      ),
    );
    inspect.append(button("Review terms", () => showPayment(p), "quiet"));
    row.append(invoice, amount, state, evidence, inspect);
    t.body.append(row);
  }
  host.append(t.wrap);
  main.append(
    note(
      "A memory grant and a payment approval are separate decisions. This dashboard reviews proposals; it does not execute payments. The simulator checks permissions again at execution.",
    ),
  );
}
function terms(p) {
  const n = el("div", "payment-terms");
  for (const [label, value] of [
    ["Invoice", p.terms.invoice_id],
    ["Supplier", supplierName(p.terms.supplier_id)],
    ["Amount (minor units)", `${p.terms.amount_minor} ${p.terms.currency}`],
    ["Display amount", money(p.terms)],
    ["Bank account", p.terms.bank_account],
    ["Evidence memory", p.terms.memory_id],
    ["Claim verification", p.terms.claim_verification_id || "Missing"],
  ])
    n.append(summary(label, value));
  return n;
}
function showPayment(p) {
  const content = $("#detail-content");
  content.replaceChildren();
  $("#detail-kind").textContent = "SIMULATED PAYMENT";
  const title = el("h2", "", `Review ${p.terms.invoice_id}`);
  title.id = "detail-title";
  content.append(
    title,
    statusBadge(p.status),
    terms(p),
    fact("Exact payment fingerprint", p.fingerprint, true, true),
  );
  if (p.approval_expires_at)
    content.append(
      el("p", "live-note", `Approval expires ${date(p.approval_expires_at)}`),
    );
  const blockers = snapshot.payment_blockers[p.id] || [];
  if (blockers.length)
    content.append(
      note(`Current blockers: ${blockers.map(human).join("; ")}`, true),
    );
  content.append(
    button(
      "Inspect evidence memory →",
      () => showMemory(p.terms.memory_id),
      "quiet",
    ),
  );
  if (p.receipt_id)
    content.append(fact("Simulated receipt", p.receipt_id, true, true));
  const actions = el("div", "form-actions");
  if (["pending_review", "approved"].includes(p.status)) {
    const approve = button(
      p.status === "approved"
        ? "Renew exact-term approval"
        : "Approve exact terms",
      () => approvePayment(p),
      "primary",
    );
    approve.disabled = blockers.length > 0;
    actions.append(
      approve,
      button("Cancel proposal", () => cancelPayment(p), "danger"),
    );
  }
  content.append(actions);
  if (!$("#detail-dialog").open) $("#detail-dialog").showModal();
}
function approvePayment(p) {
  decisionDialog(
    "Approve exact payment terms",
    "Authorize only the terms displayed below. This approval does not execute a payment.",
    "Confirm exact-term approval",
    (grid) => {
      const n = terms(p);
      n.classList.add("full");
      grid.append(n, fact("Reviewed fingerprint", p.fingerprint, true, true));
      expiryFields(grid);
    },
    async (data) => {
      await api(`/procurement/payments/${encodeURIComponent(p.id)}/approve`, {
        expected_fingerprint: p.fingerprint,
        expires_at: expiry(data),
        reason: data.get("reason").trim(),
      });
      return "Exact payment terms approved. No payment was executed.";
    },
  );
}
function cancelPayment(p) {
  decisionDialog(
    "Cancel payment proposal",
    "This proposal can no longer execute. A later workflow may create a new proposal requiring its own review.",
    "Confirm cancellation",
    (grid) => {
      const n = terms(p);
      n.classList.add("full");
      grid.append(n);
    },
    async (data) => {
      await api(`/procurement/payments/${encodeURIComponent(p.id)}/cancel`, {
        reason: data.get("reason").trim(),
      });
      return "Payment proposal cancelled.";
    },
    true,
  );
}
function renderRetrieval() {
  const main = $("#main");
  main.append(
    heading(
      "Retrieval lab",
      "See which memories can enter context for a specific query, action, and target.",
    ),
  );
  const grid = el("div", "grid"),
    formPanel = panel("Check a retrieval"),
    resultPanel = panel("Retrieval decision"),
    form = el("form", "test-form panel-body");
  const query = field("Query", "query", "textarea");
  query.input.maxLength = 2000;
  query.input.placeholder = "What do we know about this supplier?";
  const action = selectField(
    "Intended action",
    "retrieve-action",
    snapshot.actions.map((a) => [
      a,
      a === "inform" ? "Information only" : human(a),
    ]),
  );
  const target = field("Exact target", "retrieve-target");
  target.input.maxLength = 200;
  target.input.placeholder = "supplier:ABC";
  target.input.required = false;
  target.wrap.hidden = true;
  const mode = selectField("Search method", "mode", [
    ["lexical", "Lexical token search"],
    ...(snapshot.embeddings.enabled
      ? [["semantic", "Local semantic search"]]
      : []),
  ]);
  mode.input.value = snapshot.retrieval_mode;
  const threshold = field("Minimum cosine score", "score", "number", "0.25");
  threshold.input.min = "-1";
  threshold.input.max = "1";
  threshold.input.step = "0.05";
  threshold.wrap.hidden = mode.input.value !== "semantic";
  action.input.addEventListener("change", () => {
    target.wrap.hidden = action.input.value === "inform";
    target.input.required = !target.wrap.hidden;
  });
  mode.input.addEventListener("change", () => {
    threshold.wrap.hidden = mode.input.value !== "semantic";
  });
  const fields = el("div", "form-grid");
  fields.append(action.wrap, mode.wrap, target.wrap, threshold.wrap);
  form.append(query.wrap, fields);
  const actions = el("div", "form-actions"),
    submit = el("button", "primary", "Check retrieval →");
  submit.type = "submit";
  actions.append(submit);
  form.append(actions);
  formPanel.append(form);
  resultPanel.append(
    empty(
      "No retrieval checked yet",
      "Run a query to inspect allowed context and the reasons other candidates were blocked.",
    ),
  );
  grid.append(formPanel, resultPanel);
  main.append(grid);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    const started = epoch;
    try {
      const result = await api("/retrieve", {
        query: query.input.value,
        action: action.input.value,
        target: target.wrap.hidden ? null : target.input.value.trim(),
        mode: mode.input.value,
        min_score: Number(threshold.input.value),
        limit: 10,
      });
      if (started !== epoch) return;
      resultPanel.replaceChildren();
      const h = el("div", "panel-head");
      h.append(el("h2", "", "Retrieval decision"));
      resultPanel.append(h);
      const body = el("div", "panel-body"),
        counts = el("div", "result-counts");
      counts.append(
        badge(`${result.allowed.length} allowed`, "green"),
        badge(`${result.blocked.length} blocked`, "amber"),
      );
      body.append(
        counts,
        el(
          "p",
          "result-meta",
          `${human(result.mode)} · ${human(result.action)}${result.target ? " → " + result.target : ""}`,
        ),
      );
      if (result.unindexed_count)
        body.append(
          note(
            `${result.unindexed_count} nonrevoked memories were excluded because they need compatible embeddings.`,
            true,
          ),
        );
      if (!result.allowed.length && !result.blocked.length)
        body.append(
          el("p", "muted", "No candidates matched this query and threshold."),
        );
      resultPanel.append(body);
      for (const m of result.allowed) {
        const card = el("div", "result-card"),
          title = el("div", "result-title");
        title.append(
          badge("allowed", "green"),
          el(
            "span",
            "mono muted",
            `Score ${Number(result.scores[m.id]).toFixed(3)}`,
          ),
        );
        if (result.context_reviews[m.id])
          title.append(badge("reviewed exception", "amber"));
        if (result.claim_verifications[m.id])
          title.append(badge("claim checked by reviewer", "green"));
        else if (m.claim) title.append(badge("unverified claim", "amber"));
        card.append(
          title,
          el("p", "", m.content),
          button(`Inspect ${short(m.id)} →`, () => showMemory(m.id), "quiet"),
        );
        resultPanel.append(card);
      }
      for (const m of result.blocked) {
        const card = el("div", "result-card");
        card.append(
          badge("blocked", "amber"),
          el("p", "", m.reasons.map(human).join(" · ")),
          el("small", "mono", m.memory_id),
        );
        resultPanel.append(card);
      }
      notify(
        "Retrieval checked and recorded in the audit log. Refresh to load the latest snapshot.",
      );
    } catch (error) {
      if (started === epoch) notify(error.message, true);
    } finally {
      submit.disabled = false;
    }
  });
}
function renderActivity() {
  const main = $("#main");
  main.append(
    heading(
      "Audit log",
      "Follow recorded decisions, scoped approvals, and changes to memory lineage.",
    ),
  );
  const toolbar = el("div", "toolbar"),
    search = el("input"),
    host = el("div", "panel");
  search.type = "search";
  search.placeholder = "Search event, actor, or record ID";
  search.setAttribute("aria-label", "Search audit events");
  search.value = activitySearch;
  toolbar.append(
    search,
    el(
      "span",
      "count",
      `Latest ${snapshot.events.length} of ${snapshot.event_count} events`,
    ),
  );
  main.append(toolbar, host);
  const update = () => {
    const records = snapshot.events.filter((e) =>
      JSON.stringify(e)
        .toLocaleLowerCase()
        .includes(activitySearch.toLocaleLowerCase()),
    );
    activityPage = Math.min(
      activityPage,
      Math.max(1, Math.ceil(records.length / 20)),
    );
    host.replaceChildren();
    if (!records.length) {
      host.append(
        empty(
          "No matching activity",
          "Recorded decisions will appear here. Clear your search to show all loaded events.",
        ),
      );
      return;
    }
    for (const e of records.slice((activityPage - 1) * 20, activityPage * 20)) {
      const row = el("div", "list-row"),
        body = el("div"),
        title = el("div", "result-title");
      title.append(
        el("strong", "", human(e.kind)),
        el("small", "muted", date(e.created_at)),
      );
      body.append(
        title,
        el("p", "", `${e.actor} · ${e.subject_ids.map(short).join(", ")}`),
      );
      const details = el("details", "event-details");
      details.append(
        el("summary", "", "Decision details"),
        el(
          "pre",
          "",
          JSON.stringify(
            { event_id: e.id, subjects: e.subject_ids, ...e.detail },
            null,
            2,
          ),
        ),
      );
      body.append(details);
      row.append(el("span", "status-dot"), body);
      host.append(row);
    }
    host.append(
      pagination(records.length, activityPage, 20, (value) => {
        activityPage = value;
        update();
      }),
    );
  };
  search.addEventListener("input", () => {
    activitySearch = search.value;
    activityPage = 1;
    update();
  });
  update();
}
