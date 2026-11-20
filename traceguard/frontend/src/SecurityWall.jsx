import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, ArrowRight, Check, CircleAlert, LockKeyhole, RefreshCw, Shield, ShieldAlert, ShieldCheck, Siren, Wifi } from "lucide-react";

async function readJson(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `${path} returned HTTP ${response.status}`);
  return { data, response };
}

const DRILLS = {
  normal: { label: "Expected nightly sync", summary: "Baseline traffic using the documented integration profile." },
  downgrade: { label: "Client downgrade + export", summary: "Older client, off-window export burst, then download and delete." },
  rogue: { label: "Rogue agent on vendor path", summary: "Unexpected agent attempts a high-volume bank-details operation." },
  canary: { label: "Legacy key canary", summary: "A retired credential identifier triggers the deterministic tripwire." },
};

const RISK_LABELS = {
  key: "Credential",
  user_agent: "Client fingerprint",
  network: "Network context",
  behavior: "Behavior pattern",
};

function ratingName(score) {
  if (score >= 85) return "Hardened";
  if (score >= 70) return "Guarded";
  if (score >= 50) return "Needs work";
  return "At risk";
}

function providerSummary(entries) {
  const providerActions = ["vendor_bank_change.zoho_forward_error", "vendor_bank_change.zoho_applied", "vendor_bank_change.forward_error", "vendor_bank_change.forward_rejected", "vendor_bank_change.qbo_error", "vendor_bank_change.qbo_ui_confirmed"];
  const latest = (entries || []).find(row => providerActions.includes(row.action));
  if (!latest) return { label: "No recent provider result", detail: "No finance write result was found in the recent audit window.", failed: false };
  const meta = (() => { try { return JSON.parse(latest.meta || "{}"); } catch { return {}; } })();
  if (/_error|rejected/.test(latest.action)) {
    const code = String(meta.error || "").match(/HTTP\s+(\d{3})/i)?.[1];
    return { label: code ? `Provider rejected request · HTTP ${code}` : "Provider write failed", detail: "Orbit recorded no success confirmation for this write.", failed: true };
  }
  if (/\.applied|\.confirmed/.test(latest.action)) {
    return { label: "Provider confirmed a write", detail: "The latest recorded provider action has a confirmation event.", failed: false };
  }
  return { label: "Finance action recorded", detail: "Review the audit event before claiming provider completion.", failed: false };
}

function CheckRow({ title, detail, score, max, status }) {
  const state = status || (score === max ? "pass" : score > 0 ? "partial" : "gap");
  return <article className={`wall-check ${state}`}>
    <span className="wall-check-icon">{state === "pass" ? <Check size={15}/> : state === "partial" ? <CircleAlert size={15}/> : <AlertTriangle size={15}/>}</span>
    <div className="wall-check-copy"><strong>{title}</strong><small>{detail}</small></div>
    <b className="wall-check-score">{score}/{max}</b>
  </article>;
}

export default function SecurityWall() {
  const [health, setHealth] = useState(null);
  const [audit, setAudit] = useState(null);
  const [headers, setHeaders] = useState(null);
  const [presets, setPresets] = useState({});
  const [scenario, setScenario] = useState("rogue");
  const [result, setResult] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function refresh() {
    setError("");
    try {
      const [healthResult, auditResult, presetResult] = await Promise.all([
        readJson("/api/health"),
        readJson("/api/audit?limit=200"),
        readJson("/api/engine/presets"),
      ]);
      setHealth(healthResult.data);
      setAudit(auditResult.data);
      setPresets(presetResult.data.presets || {});
      setHeaders({
        csp: Boolean(healthResult.response.headers.get("content-security-policy")),
        frame: healthResult.response.headers.get("x-frame-options")?.toUpperCase() === "DENY" || healthResult.response.headers.get("content-security-policy")?.includes("frame-ancestors 'none'"),
        nosniff: healthResult.response.headers.get("x-content-type-options")?.toLowerCase() === "nosniff",
        referrer: healthResult.response.headers.get("referrer-policy")?.toLowerCase() === "no-referrer",
      });
      setUpdatedAt(new Date());
    } catch (e) {
      setError(e.message || "Could not read the current security status.");
    }
  }

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 15000);
    return () => clearInterval(timer);
  }, []);

  async function runDrill(event) {
    event.preventDefault();
    const payload = presets[scenario];
    if (!payload) return;
    setBusy(true);
    setError("");
    try {
      const response = await readJson("/api/engine/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      setResult(response.data);
      await refresh();
    } catch (e) {
      setError(e.message || "The analysis drill could not run.");
    } finally {
      setBusy(false);
    }
  }

  const gate = health?.request_gate || {};
  const latestProvider = providerSummary(audit?.entries);
  const isHttps = typeof window !== "undefined" && window.location.protocol === "https:";
  const localHost = typeof window !== "undefined" && ["localhost", "127.0.0.1", "::1"].includes(window.location.hostname);
  const headerCount = headers ? Object.values(headers).filter(Boolean).length : 0;
  const checks = useMemo(() => {
    const gateReady = Boolean(gate.configured && gate.can_hold);
    const approvalReady = /active identity/i.test(gate.enforcement || "") && /vendor scope/i.test(gate.enforcement || "") && /exact Finance approval/i.test(gate.enforcement || "");
    const auditReady = Boolean(audit?.verification?.intact);
    const providerReady = Boolean(gate.upstream_configured && gate.can_forward);
    const securityHeaderScore = headers ? Math.round((headerCount / 4) * 15) : 0;
    const boundaryScore = (isHttps ? 10 : 0) + (localHost ? 5 : 0);
    const providerScore = providerReady ? (latestProvider.failed ? 5 : 10) : 0;
    return [
      { title: "Request-time gate", detail: gateReady ? "Live gate is configured and accepts requests for policy review." : "The live request gate is not fully configured.", score: gateReady ? 20 : 0, max: 20 },
      { title: "Independent approval", detail: approvalReady ? "Active identity, vendor scope, and exact Finance approval are required." : "The approval policy is missing or could not be verified.", score: approvalReady ? 15 : 0, max: 15 },
      { title: "Audit integrity", detail: auditReady ? `${audit.verification.chain_length} audit entries; hash chain verifies.` : "Audit chain is broken or verification is unavailable.", score: auditReady ? 15 : 0, max: 15 },
      { title: "Finance provider", detail: providerReady ? latestProvider.label : "Provider path is not configured for writes.", score: providerScore, max: 10, status: providerReady && latestProvider.failed ? "partial" : undefined },
      { title: "Browser security headers", detail: headers ? `${headerCount} of 4 checks present: CSP, frame protection, nosniff, and referrer policy.` : "Waiting for the browser header check.", score: securityHeaderScore, max: 15 },
      { title: "Production boundary", detail: `${isHttps ? "HTTPS enabled" : "HTTP only"}; ${localHost ? "running on this machine" : "host is not localhost"}. Console SSO and direct-write lockout are not verified here.`, score: boundaryScore, max: 25, status: boundaryScore === 25 ? "pass" : boundaryScore > 0 ? "partial" : "gap" },
    ];
  }, [gate.configured, gate.can_hold, gate.can_forward, gate.upstream_configured, gate.enforcement, audit?.verification?.intact, audit?.verification?.chain_length, headers, headerCount, isHttps, localHost, latestProvider.failed, latestProvider.label]);

  const score = checks.reduce((sum, item) => sum + item.score, 0);
  const selectedDrill = DRILLS[scenario] || { label: scenario, summary: "Run the selected detector profile." };
  const wallSteps = [
    ["Caller identity", Boolean(gate.configured), "Credential and employee status"],
    ["Vendor scope", Boolean(gate.configured), "Allowed vendor boundary"],
    ["Finance approval", Boolean(gate.can_hold), "Independent approver required"],
    ["Exact details", Boolean(gate.can_hold), "Approved fingerprint must match"],
    ["Provider write", Boolean(gate.can_forward), "Forward only after all checks"],
  ];

  return <div className="security-wall">
    <section className="op-page-title wall-heading">
      <div className="op-eyebrow"><Shield size={15}/> LIVE DEFENSE CONTROLS</div>
      <div className="wall-heading-row"><div><h1>Security wall</h1><p>See what Orbit is enforcing now, then run a request-risk drill against the real scoring engine.</p></div><button className="op-secondary" onClick={refresh} disabled={busy}><RefreshCw size={14}/> Refresh live checks</button></div>
    </section>

    {error && <div className="wall-error" role="status"><AlertTriangle size={15}/>{error}</div>}

    <section className="wall-overview">
      <article className="wall-rating-card">
        <div className="wall-rating-ring" style={{ "--rating": `${score}%` }}><div><strong>{health ? score : "—"}</strong><span>/ 100</span></div></div>
        <div className="wall-rating-copy"><span className="wall-kicker">LIVE DEFENSE RATING</span><h2>{health ? ratingName(score) : "Checking…"}</h2><p>Built from the checks shown below. This is an observable posture score, not a penetration-test result.</p><small>{updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : "Waiting for live controls"}</small></div>
      </article>
      <article className="wall-provider-card">
        <div className={`wall-status-icon ${latestProvider.failed ? "warn" : gate.can_forward ? "ok" : "off"}`}>{latestProvider.failed ? <CircleAlert size={19}/> : gate.can_forward ? <ShieldCheck size={19}/> : <ShieldAlert size={19}/>}</div>
        <div><span className="wall-kicker">PROVIDER STATUS</span><h3>{gate.provider === "zoho_books_india" ? "Zoho Books India" : gate.provider || "No provider"}</h3><p>{latestProvider.label}</p><small>{latestProvider.detail}</small></div>
        <span className={`wall-live-pill ${latestProvider.failed ? "warn" : gate.upstream_configured ? "ok" : "off"}`}><i/>{latestProvider.failed ? "REVIEW" : gate.upstream_configured ? "CONFIGURED" : "OFFLINE"}</span>
      </article>
    </section>

    <section className="wall-section">
      <div className="wall-section-heading"><div><span className="wall-kicker">ENFORCEMENT PATH</span><h2>One write path, five checks</h2><p>Every node below reflects the current gate policy; provider forwarding remains last.</p></div><span className="wall-db-state"><Activity size={14}/>{health?.database_connected ? `${health.database_provider} · ONLINE` : "DATABASE CHECK NEEDED"}</span></div>
      <div className="wall-path">
        {wallSteps.map(([title, active, detail], index) => <div className={`wall-path-step ${active ? "active" : "inactive"}`} key={title}>
          <span className="wall-path-index">0{index + 1}</span><span className="wall-path-icon">{index === 0 ? <LockKeyhole size={16}/> : index === 4 ? <Wifi size={16}/> : <ShieldCheck size={16}/>}</span><strong>{title}</strong><small>{detail}</small>{index < wallSteps.length - 1 && <ArrowRight className="wall-path-arrow" size={15}/>}
        </div>)}
      </div>
    </section>

    <section className="wall-layout">
      <section className="wall-section wall-checks-panel">
        <div className="wall-section-heading"><div><span className="wall-kicker">SCORE BREAKDOWN</span><h2>Evidence behind the rating</h2></div><small className="wall-score-total">{score}/100</small></div>
        <div className="wall-check-list">{checks.map(item => <CheckRow key={item.title} {...item}/>)}</div>
        <p className="wall-footnote">Unverified production controls receive no points. A high score cannot prove resistance to every attack.</p>
      </section>

      <section className="wall-section wall-drill-panel">
        <div className="wall-section-heading"><div><span className="wall-kicker"><Siren size={13}/> CONTROLLED ATTACK DRILL</span><h2>Test the detector</h2></div><span className="wall-analysis-tag">ANALYSIS ONLY</span></div>
        <p className="wall-drill-intro">Choose a recorded attack pattern. Orbit scores it with the live request-analysis engine and records the result in the audit trail.</p>
        <form className="wall-drill-form" onSubmit={runDrill}>
          <label htmlFor="wall-scenario">Attack scenario</label>
          <select id="wall-scenario" value={scenario} onChange={event => setScenario(event.target.value)}>
            {Object.entries(DRILLS).filter(([id]) => presets[id]).map(([id, drill]) => <option key={id} value={id}>{drill.label}</option>)}
          </select>
          <small>{selectedDrill.summary}</small>
          <button className="op-primary" disabled={busy || !presets[scenario]}>{busy ? "Scoring request…" : "Run attack drill"}<ArrowRight size={15}/></button>
        </form>
        <div className="wall-no-write"><LockKeyhole size={14}/><span>This runs <code>/api/engine/evaluate</code> only. It does not submit a bank change or call Zoho.</span></div>
        {result && <div className={`wall-result ${result.verdict === "PASS" ? "pass" : result.verdict === "CRITICAL_CANARY" ? "critical" : "quarantine"}`}>
          <div className="wall-result-head"><div><span className="wall-kicker">ENGINE VERDICT</span><strong>{result.verdict}</strong></div><div className="wall-result-score"><b>{result.risk_score}</b><small>RISK / 100</small></div></div>
          <div className="wall-factor-list">{Object.entries(result.factors || {}).map(([name, value]) => <div className="wall-factor" key={name}><span>{RISK_LABELS[name] || name}</span><div><i style={{ width: `${Math.min(100, value)}%` }}/></div><b>{value}</b></div>)}</div>
          <ul>{(result.reasons || []).map(reason => <li key={reason}>{reason}</li>)}</ul>
          {result.recommended_response && <p className="wall-response"><b>RECOMMENDED RESPONSE</b>{result.recommended_response}</p>}
          <small className="wall-result-note">Scoring limitations: {(result.limitations || []).join(" ")}</small>
        </div>}
      </section>
    </section>

    <aside className="wall-demo-boundary"><ShieldAlert size={17}/><div><strong>Demo boundary</strong><span>This page checks the running Orbit instance and runs controlled detector scenarios. It is not an external vulnerability scan, exploit attempt, or production certification.</span></div></aside>
  </div>;
}
