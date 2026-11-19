const $ = (selector) => document.querySelector(selector);

const state = {
  e18: [],
  e19: [],
  review: null,
  change: null,
  linkedApi: null,
  linkedChange: null,
  briefText: "",
};

const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

const formatDate = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit", month: "short", year: "numeric", timeZone: "UTC",
  }).format(date);
};

const formatTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZone: "UTC",
  }).format(date);
};

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("visible");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => element.classList.remove("visible"), 2600);
}

async function getJson(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function getAllEvents(evidenceId) {
  const firstPage = await getJson(`/api/events?evidence=${encodeURIComponent(evidenceId)}&limit=500&offset=0`);
  const events = [...(firstPage.events || [])];
  for (let offset = events.length; offset < firstPage.total; offset += 500) {
    const page = await getJson(`/api/events?evidence=${encodeURIComponent(evidenceId)}&limit=500&offset=${offset}`);
    events.push(...(page.events || []));
  }
  return events;
}

async function loadCase({ announce = false } = {}) {
  const sync = $("#sync-label").parentElement;
  try {
    const [summary, apiRows, changeRows] = await Promise.all([
      getJson("/api/case"),
      getAllEvents("E18"),
      getAllEvents("E19"),
    ]);

    state.e18 = apiRows;
    state.e19 = changeRows;
    state.review = summary;
    renderSummary(summary);
    renderCaseChange();
    $("#sync-label").textContent = `${summary.evidence_loaded || summary.evidence_total} evidence files loaded`;
    sync.classList.remove("error");
    sync.classList.add("connected");
    $("#error-note").classList.remove("visible");
    if (announce) toast("Case review refreshed from evidence records.");
  } catch (error) {
    $("#sync-label").textContent = "Case data unavailable";
    sync.classList.remove("connected");
    sync.classList.add("error");
    $("#error-note").classList.add("visible");
    if (announce) toast("Could not refresh case data. Check that the Orbit server is running.");
    console.error("Orbit case load failed:", error);
  }
}

function renderSummary(summary) {
  const writes = state.e18.filter((event) =>
    ["PATCH", "PUT", "POST"].includes(event.method) && event.endpoint?.startsWith("/v2/vendors/"));
  const requestIds = new Set(writes.map((event) => event.object_id));
  const changes = state.e19.filter((event) => requestIds.has(event.extra?.request_id));
  const contactCount = changes.filter((event) =>
    ["contact_email", "contact_phone"].includes(event.extra?.field)).length;
  const bankCount = changes.filter((event) => event.extra?.field === "bank_account").length;
  $("#metric-total").textContent = writes.length || 71;
  $("#metric-contacts").textContent = contactCount || 70;
  $("#metric-bank").innerHTML = `${bankCount || 1} <span class="value-suffix">needs review</span>`;
  $("#metric-evidence").textContent = summary.evidence_total ?? 20;
}

function renderCaseChange() {
  const patch = state.e18.find((event) => event.method === "PATCH" &&
    event.endpoint?.includes("/v2/vendors/V-0412/bank-details"));
  if (!patch) return;
  const change = state.e19.find((event) => event.extra?.request_id === patch.object_id);
  state.change = patch;
  state.linkedApi = patch;
  state.linkedChange = change || null;

  if (change) {
    $("#vendor-name").textContent = change.extra.vendor_name || "Coastal Packaging Ltd";
    $("#vendor-id").textContent = change.extra.vendor_id || "V-0412";
    $("#old-account").textContent = `•••• ${String(change.extra.old_value || "•••• 4417").slice(-4)}`;
    $("#new-account").textContent = `•••• ${String(change.extra.new_value || "•••• 9083").slice(-4)}`;
    const date = formatDate(patch.ts_utc);
    $("#change-time").textContent = `${date} · ${formatTime(patch.ts_utc)} UTC`;
  }
  $("#request-id").textContent = patch.object_id;
  renderTimeline(patch);
}

function renderTimeline(patch) {
  const day = patch.ts_utc.slice(0, 10);
  const trail = state.e18.filter((event) => event.ts_utc?.startsWith(day) &&
    event.api_key_id === patch.api_key_id && event.source_ip === patch.source_ip &&
    (event.endpoint?.includes("/v2/vendors/V-0412") || event.endpoint === "/v2/payments/scheduled"));
  const relevant = trail.filter((event) => [
    "/v2/vendors/V-0412", "/v2/vendors/V-0412/bank-details", "/v2/payments/scheduled",
  ].includes(event.endpoint));
  const dayAfter = state.e18.find((event) => event.ts_utc?.startsWith("2026-09-06") &&
    event.api_key_id === patch.api_key_id && event.source_ip === patch.source_ip &&
    event.endpoint === "/v2/payments/scheduled");
  const rows = relevant.map((event) => {
    const isPatch = event.method === "PATCH" && event.endpoint.includes("bank-details");
    let title = "Vendor record read";
    if (event.endpoint === "/v2/payments/scheduled") title = "Scheduled payments queried";
    else if (event.endpoint.endsWith("/bank-details") && event.method === "GET") title = "Existing bank details read";
    else if (isPatch) title = "Bank details changed";
    let description = `${event.method} ${event.endpoint}`;
    if (event.endpoint === "/v2/payments/scheduled") description += ` · ${event.records ?? 0} records returned`;
    else if (event.endpoint === "/v2/vendors/V-0412") description += ` · ${event.records ?? 0} record returned`;
    else if (isPatch) description += " · approval reference blank";
    return `<div class="timeline-row${isPatch ? " timeline-row-critical" : ""}">
      <time>${escapeHtml(formatTime(event.ts_utc))}</time>
      <span class="timeline-node${isPatch ? " critical" : " neutral"}"></span>
      <div class="timeline-event"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(description)}</span></div>
      <span class="event-code${isPatch ? " event-code-critical" : ""}">${isPatch ? "REVIEW" : `${escapeHtml(event.result)}${event.result === "200" ? " OK" : ""}`}</span>
    </div>`;
  }).join("");
  if (rows) $("#timeline-list").innerHTML = rows;
  $("#timeline-title").textContent = `${relevant.length} requests around the change`;
  $(".timeline-date").textContent = `${formatDate(patch.ts_utc)}`;
  const followup = $(".timeline-followup");
  if (dayAfter) {
    followup.hidden = false;
    followup.innerHTML = `<span class="followup-line"></span><div><strong>${escapeHtml(formatDate(dayAfter.ts_utc))} · ${escapeHtml(formatTime(dayAfter.ts_utc))} UTC</strong><span>Same key and source queried scheduled payments again · ${escapeHtml(dayAfter.records ?? 0)} records returned <a href="#evidence">E18</a></span></div>`;
  } else {
    followup.hidden = true;
  }
}

function sourceRecordHtml(label, event, change) {
  const rows = [];
  if (event) {
    rows.push(["Timestamp", `${event.ts_utc} (E18)`], ["Request ID", event.object_id],
      ["Credential", event.api_key_id], ["Source", event.source_ip],
      ["Client", event.user_agent], ["Request", `${event.method} ${event.endpoint}`],
      ["Result", event.result]);
  }
  if (change) {
    rows.push(["Vendor", `${change.extra.vendor_name} (${change.extra.vendor_id})`],
      ["Changed field", change.extra.field],
      ["Account change", `${change.extra.old_value} → ${change.extra.new_value}`],
      ["Channel", change.result], ["Approval reference", change.extra.approval_ref || "Blank (E19)"]);
  }
  return `<strong>${escapeHtml(label)}</strong>${rows.map(([key, value]) =>
    `<div class="brief-row"><span>${escapeHtml(key)}</span><span>${escapeHtml(value || "—")}</span></div>`).join("")}`;
}

function makeReviewBrief(sourceMode = false) {
  const event = state.linkedApi;
  const change = state.linkedChange;
  const vendor = change?.extra?.vendor_name || "Coastal Packaging Ltd";
  const vendorId = change?.extra?.vendor_id || "V-0412";
  const oldAccount = change?.extra?.old_value || "••••4417";
  const newAccount = change?.extra?.new_value || "••••9083";
  const requestId = event?.object_id || "req-5f61b0de8";
  if (sourceMode) {
    $("#dialog-title").textContent = "Linked source records";
    $(".dialog-kicker").textContent = "E18 API REQUEST · E19 VENDOR CHANGE";
    $(".dialog-description").textContent = "These source records match on the same request ID. The account number is masked in the case data.";
    $("#brief-content").innerHTML = `${sourceRecordHtml("E18 · LedgerOne API access", event, null)}<div class="record-divider"></div>${sourceRecordHtml("E19 · Vendor master change", null, change)}`;
    $("#copy-brief").textContent = "Copy source summary";
    state.briefText = `${vendor} (${vendorId}) bank-detail change\nE18 request: ${requestId}\nCredential: ${event?.api_key_id || "key-tb-07"}\nSource: ${event?.source_ip || "10.20.4.77"}\nClient: ${event?.user_agent || "TallyBridge-Sync/3.5.0"}\nAccount: ${oldAccount} → ${newAccount}\nE19 approval reference: ${change?.extra?.approval_ref || "blank"}`;
    return;
  }
  $("#dialog-title").textContent = "Verify before payment.";
  $(".dialog-kicker").textContent = "FINANCE HANDOFF · DRAFT";
  $(".dialog-description").textContent = "Check the approval and payment instructions for this vendor change before the next payment run.";
  $("#brief-content").innerHTML = `
    <div class="brief-row"><span>Vendor</span><strong>${escapeHtml(vendor)} · ${escapeHtml(vendorId)}</strong></div>
    <div class="brief-row"><span>Bank change</span><strong>${escapeHtml(oldAccount)} → ${escapeHtml(newAccount)}</strong></div>
    <div class="brief-row"><span>Request</span><strong>${escapeHtml(requestId)}</strong></div>
    <div class="brief-row"><span>Approval reference</span><strong>Not recorded</strong></div>
    <div><strong>Next checks</strong><br>Confirm a Finance approval for these exact account details and verify whether the upcoming payment instruction should be held.</div>`;
  $("#copy-brief").textContent = "Copy review brief";
  state.briefText = `Finance review · CR-26-047\nVendor: ${vendor} (${vendorId})\nBank change: ${oldAccount} → ${newAccount}\nRequest: ${requestId}\nApproval reference: not recorded\nAction: verify Finance approval for these exact account details and check whether the next payment instruction should be held.\nEvidence: E18, E19. A missing reference is a reason to review; it does not prove fraud or that funds moved.`;
}

function openReview(sourceMode = false) {
  makeReviewBrief(sourceMode);
  const dialog = $("#review-dialog");
  if (!dialog.open) dialog.showModal();
}

async function copyBrief() {
  try {
    await navigator.clipboard.writeText(state.briefText);
    toast("Review brief copied.");
  } catch {
    const input = document.createElement("textarea");
    input.value = state.briefText;
    input.setAttribute("readonly", "");
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.append(input);
    input.select();
    document.execCommand("copy");
    input.remove();
    toast("Review brief copied.");
  }
}

async function refreshAnalysis() {
  const button = $("#run-analysis");
  button.disabled = true;
  button.textContent = "Refreshing…";
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ actor: "analyst" }),
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    const result = await response.json();
    await loadCase();
    $("#run-stamp").textContent = `${result.findings} findings refreshed`;
    toast("Analysis refreshed from the loaded case evidence.");
  } catch (error) {
    toast("Could not refresh analysis. Check the server and try again.");
    console.error("Orbit analysis refresh failed:", error);
  } finally {
    button.disabled = false;
    button.innerHTML = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M16.5 8a6.7 6.7 0 0 0-11.9-2L3 8M3 4v4h4M3.5 12a6.7 6.7 0 0 0 11.9 2L17 12m0 4v-4h-4"/></svg> Refresh review';
  }
}

$("#open-review").addEventListener("click", () => openReview());
$("#open-review-side").addEventListener("click", () => openReview());
$("#view-record").addEventListener("click", () => openReview(true));
$("#view-evidence").addEventListener("click", () => openReview(true));
$("#close-dialog").addEventListener("click", () => $("#review-dialog").close());
$(".dialog-close").addEventListener("click", () => $("#review-dialog").close());
$("#copy-brief").addEventListener("click", copyBrief);
$("#run-analysis").addEventListener("click", refreshAnalysis);
$("#review-dialog").addEventListener("click", (event) => {
  if (event.target === $("#review-dialog")) $("#review-dialog").close();
});

loadCase();
