import { useEffect, useState } from "react";
import { ArrowRight, Check, CircleAlert, KeyRound, LockKeyhole, RefreshCw, ShieldCheck } from "lucide-react";
import SecurityWall from "./SecurityWall.jsx";
import "./operator.css";

async function api(path, { token, ...options } = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(options.headers || {}) },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

const moneyFields = [
  ["bank_name", "Bank name"],
  ["account_holder", "Account holder"],
  ["account_number", "Account number"],
  ["routing_code", "Routing code"],
  ["country", "Country"],
];

export default function App() {
  const [page, setPage] = useState("overview");
  const [health, setHealth] = useState(null);
  const [tokenInput, setTokenInput] = useState("");
  const [token, setToken] = useState("");
  const [requests, setRequests] = useState([]);
  const [selected, setSelected] = useState(null);
  const [details, setDetails] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [simulation, setSimulation] = useState(false);
  const [simulatedRequests, setSimulatedRequests] = useState([]);
  const [simulatedSelection, setSimulatedSelection] = useState(null);

  async function refreshStatus() {
    try { setHealth(await api("/health")); } catch (e) { setError(e.message); }
  }
  async function loadQueue(auth = token) {
    if (!auth) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await api("/gate/requests", { token: auth });
      const actionable = (result.requests || []).filter(row => ["HELD", "APPROVED_PENDING_PROVIDER"].includes(row.status));
      const first = actionable.find(row => row.status === "HELD") || actionable[0] || null;
      setRequests(actionable);
      setToken(auth);
      setTokenInput("");
      setSelected(first); setDetails(null); setConfirmed(false);
      if (first) {
        const detail = await api(`/gate/requests/${encodeURIComponent(first.gate_request_id)}`, { token: auth });
        setDetails(detail);
      }
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }
  async function loadSimulation() {
    setError("");
    try {
      const result = await api("/simulation/requests");
      const rows = result.requests || [];
      setSimulatedRequests(rows);
      setSimulatedSelection(rows[0] || null);
      setSimulation(true);
    } catch (e) { setError(e.message); }
  }
  async function openRequest(row) {
    if (simulation) { setSimulatedSelection(row); return; }
    setSelected(row); setDetails(null); setConfirmed(false); setError("");
    try { setDetails(await api(`/gate/requests/${encodeURIComponent(row.gate_request_id)}`, { token })); }
    catch (e) { setError(e.message); }
  }
  async function approveRequest(event) {
    event.preventDefault();
    if (!details || !confirmed) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await api(`/gate/requests/${encodeURIComponent(details.gate_request_id)}/approvals`, {
        token, method: "POST", body: JSON.stringify({ bank_details: details.bank_details, confirm_exact_details: true }),
      });
      setNotice(`Approval recorded. Request status: ${result.status}.`);
      await loadQueue(token);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  useEffect(() => { refreshStatus(); const id = setInterval(refreshStatus, 15000); return () => clearInterval(id); }, []);
  const gate = health?.request_gate || {};
  const apiOnline = health?.status === "ok";
  const visibleRequests = simulation ? simulatedRequests : requests;
  const visibleSelected = simulation ? simulatedSelection : selected;
  const visibleDetails = simulation ? simulatedSelection : details;

  return <div className="operator-app">
    <header className="op-header">
      <a className="op-brand" href="/" aria-label="Orbit home"><img src="/assets/orbit-mascot.svg" alt=""/><span>orbit<span>.</span></span></a>
      <nav aria-label="Primary navigation">
        <button className={page === "overview" ? "active" : ""} onClick={() => setPage("overview")}>Overview</button>
        <button className={page === "approvals" ? "active" : ""} onClick={() => setPage("approvals")}>Finance approvals</button>
        <button className={page === "security" ? "active" : ""} onClick={() => setPage("security")}>Security wall</button>
      </nav>
      <div className="op-live"><i className={apiOnline ? "online" : ""}/>{apiOnline ? "Protection online" : "Connecting"}</div>
    </header>

    <main className="op-main">
      {page === "overview" ? <>
        <section className="op-hero">
          <video className="op-hero__orbit" autoPlay muted loop playsInline preload="metadata" aria-hidden="true" tabIndex={-1}>
            <source src="/assets/solace-orbit.mp4" type="video/mp4" />
          </video>
          <div className="op-eyebrow"><ShieldCheck size={15}/> VENDOR PAYMENT PROTECTION</div>
          <h1>Stop unauthorized bank changes<br/><em>before they reach payment.</em></h1>
          <p>Orbit puts an independent approval gate in the write path to your finance system. Each change is checked against the caller, vendor, and exact bank details before it can be applied.</p>
          <div className="op-hero-actions"><button className="op-primary" onClick={() => setPage("approvals")}>Open Finance approvals <ArrowRight size={16}/></button><button className="op-secondary" onClick={() => setPage("security")}>Open Security wall <ShieldCheck size={15}/></button></div>
        </section>

        <section className="op-status-grid" aria-label="Protection status">
          <article className="op-status-card"><span>API</span><strong className={apiOnline ? "good" : "bad"}>{apiOnline ? "Online" : "Unavailable"}</strong><small>{health?.database_provider || "Waiting for service"}</small></article>
          <article className="op-status-card"><span>WRITE GATE</span><strong className={gate.can_forward ? "good" : "bad"}>{gate.can_forward ? "Enforcing approvals" : "Not ready"}</strong><small>{gate.provider || "Provider not configured"}</small></article>
          <article className="op-status-card"><span>LAST SYNC</span><strong>{health?.last_sync_utc ? new Date(health.last_sync_utc).toLocaleString() : "—"}</strong><small>Service health check</small></article>
        </section>

        <section className="op-workflow">
          <div className="op-section-heading"><div><span className="op-eyebrow">EVERY WRITE FOLLOWS THE SAME POLICY</span><h2>One controlled path to payment.</h2></div></div>
          <div className="op-steps">
            <article><b>01</b><LockKeyhole/><h3>Authenticate the caller</h3><p>Check active identity, credential status, role, and vendor scope on every request.</p></article>
            <article><b>02</b><CircleAlert/><h3>Hold for independent review</h3><p>Keep bank details encrypted while a separate Finance approver reviews the exact values.</p></article>
            <article><b>03</b><Check/><h3>Apply only the approved change</h3><p>Forward matching details to Zoho Books. Mismatches and failed checks remain blocked.</p></article>
          </div>
        </section>

        <section className="op-callout"><div><span className="op-eyebrow">CONNECTED FINANCE PROVIDER</span><h2>{gate.provider === "zoho_books_india" ? "Zoho Books India" : gate.provider || "Finance provider"}</h2><p>{gate.can_forward ? "Vendor bank updates are routed through Orbit after exact, independent Finance approval." : "Configure the provider and gate credentials to enable request-time protection."}</p></div><button className="op-secondary" onClick={refreshStatus}><RefreshCw size={15}/> Refresh status</button></section>
      </> : page === "security" ? <SecurityWall/> : <>
        <section className="op-page-title"><div className="op-eyebrow"><KeyRound size={14}/> FINANCE OPERATIONS</div><h1>Approval queue</h1><p>Review requests awaiting Finance approval or provider completion. Approval requires confirmation of the exact submitted details.</p><button className="op-secondary op-simulation-toggle" onClick={() => simulation ? setSimulation(false) : loadSimulation()}>{simulation ? "Return to live queue" : "Preview simulated queue"}</button>{simulation && <div className="op-simulation-note">SIMULATION · 3 awaiting Finance · 2 awaiting Zoho · 1 completed in Zoho Books. No approvals or provider writes are made.</div>}</section>
        {simulation ? <div className="op-queue-layout">
          <section className="op-queue"><div className="op-queue-head"><h2>Simulated requests</h2></div>
            {visibleRequests.map(row => <button className={`op-request ${visibleSelected?.gate_request_id === row.gate_request_id ? "selected" : ""}`} key={row.gate_request_id} onClick={() => openRequest(row)}><span><b>{row.vendor_id}</b><small>{row.requester} · {new Date(row.created_utc).toLocaleString()}</small></span><strong>{row.status === "APPROVED_PENDING_PROVIDER" ? "PROVIDER FOLLOW-UP" : row.status === "APPLIED" ? "COMPLETED IN ZOHO" : "AWAITING FINANCE"}</strong></button>)}
          </section>
          <section className="op-review"><h2>Simulated request details</h2>{visibleDetails && <>
            <dl className="op-meta"><div><dt>Vendor</dt><dd>{visibleDetails.vendor_id}</dd></div><div><dt>Requester</dt><dd>{visibleDetails.requester}</dd></div><div><dt>Request ID</dt><dd>{visibleDetails.request_id}</dd></div><div><dt>Account suffix</dt><dd>•••• {visibleDetails.account_last4}</dd></div></dl>
            <h3>Simulated bank details</h3><div className="op-bank-fields">{moneyFields.map(([key, label]) => <label key={key}>{label}<input readOnly value={visibleDetails.bank_details[key]}/></label>)}</div>
            <div className="op-follow-up"><strong>{visibleDetails.status === "HELD" ? "Awaiting Finance approval" : visibleDetails.status === "APPLIED" ? "Completed in Zoho Books" : "Finance approval recorded"}</strong><span>{visibleDetails.status === "HELD" ? "This request remains unapproved in the simulation." : visibleDetails.status === "APPLIED" ? `Simulated Zoho completion · ${visibleDetails.upstream_reference}` : "This request is awaiting Zoho provider completion in the simulation."}</span></div>
          </>}</section>
        </div> : !token ? <form className="op-auth" onSubmit={e => { e.preventDefault(); loadQueue(tokenInput); }}>
          <label htmlFor="finance-token">Finance approver token</label>
          <div><input id="finance-token" type="password" autoComplete="off" value={tokenInput} onChange={e => setTokenInput(e.target.value)} placeholder="Paste your approver token" required/><button className="op-primary" disabled={busy}>{busy ? "Connecting…" : "Connect"}</button></div>
          <small>The token stays in this page’s memory and is cleared when you leave.</small>
        </form> : <div className="op-queue-layout">
          <section className="op-queue"><div className="op-queue-head"><h2>Requests needing attention</h2><button className="op-secondary" onClick={() => loadQueue()}><RefreshCw size={14}/> Refresh</button></div>
            {visibleRequests.length ? visibleRequests.map(row => <button className={`op-request ${visibleSelected?.gate_request_id === row.gate_request_id ? "selected" : ""}`} key={row.gate_request_id} onClick={() => openRequest(row)}><span><b>{row.vendor_id}</b><small>{row.requester} · {new Date(row.created_utc).toLocaleString()}</small></span><strong>{row.status === "APPROVED_PENDING_PROVIDER" ? "PROVIDER FOLLOW-UP" : row.status === "APPLIED" ? "COMPLETED IN ZOHO" : row.status === "HELD" ? "AWAITING FINANCE" : row.status}</strong></button>) : <p className="op-empty">No requests are waiting for approval or provider follow-up.</p>}
            <button className="op-text-button" onClick={() => { setToken(""); setRequests([]); setDetails(null); }}>Disconnect approver session</button>
          </section>
          <section className="op-review"><h2>Request details</h2>{!visibleDetails ? <p className="op-empty">Select a request to review its exact bank-change details.</p> : <>
            <dl className="op-meta"><div><dt>Vendor</dt><dd>{visibleDetails.vendor_id}</dd></div><div><dt>Requester</dt><dd>{visibleDetails.requester}</dd></div><div><dt>Request ID</dt><dd>{visibleDetails.request_id}</dd></div><div><dt>Account suffix</dt><dd>•••• {visibleDetails.account_last4}</dd></div></dl>
            {!simulation && visibleDetails.sandbox_reopened_utc && <div className="op-follow-up"><strong>Reopened for sandbox staff review</strong><span>Earlier approval history remains in the audit log. A new Finance approval is required.</span></div>}
            <h3>Submitted bank details</h3><div className="op-bank-fields">{moneyFields.map(([key,label]) => <label key={key}>{label}<input readOnly value={visibleDetails.bank_details?.[key] || ""}/></label>)}</div>
            {visibleDetails.status === "HELD" ? <form onSubmit={approveRequest}><label className="op-confirm"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/><span>I independently verified these exact bank details for this vendor.</span></label><button className="op-primary" disabled={busy || !confirmed}>{busy ? "Recording…" : "Approve exact details"}<ArrowRight size={15}/></button></form> : visibleDetails.status === "APPLIED" ? <div className="op-follow-up"><strong>Completed in Zoho Books</strong><span>Zoho confirmed this change{visibleDetails.upstream_status ? ` (HTTP ${visibleDetails.upstream_status})` : ""}.</span></div> : <div className="op-follow-up"><strong>Finance approval already recorded</strong><span>Provider completion is pending{visibleDetails.upstream_status ? ` (HTTP ${visibleDetails.upstream_status})` : ""}. Check the vendor record in Zoho Books before taking further action.</span></div>}
          </>}</section>
        </div>}
      </>}
      {(error || notice) && <div className={`op-message ${error ? "error" : "success"}`} role="status">{error || notice}<button onClick={() => { setError(""); setNotice(""); }} aria-label="Dismiss">×</button></div>}
    </main>
    <footer className="op-footer"><span>Orbit</span><span>Vendor bank changes require active identity, vendor scope, and independent Finance approval.</span><a href="/docs">API documentation ↗</a></footer>
  </div>;
}
