import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Activity, AlertTriangle, ArrowDownRight, ArrowRight, Check, ChevronRight, CircleHelp, Clock3, Copy, Database, FileClock, Fingerprint, Network, Radio, Shield, ShieldAlert, ShieldCheck, Siren, Waypoints } from "lucide-react";

const EngineCharts = lazy(() => import("./EngineCharts.jsx"));

const NAV = ["Threat topology", "Clock forensics", "Detection engine", "Hardening", "Validation"];
const CHECKS = ["Snapshot raw E01 logs", "Snapshot raw E02 logs", "Snapshot raw E05 logs", "Snapshot E15 network flows", "Snapshot E18/E19 records", "Hash evidence files", "Record collection timestamps", "Preserve original timestamps", "Record evidence custodian", "Preserve credential state before rotation", "Record evidence hashes and storage references"];
const REFS = ["E01", "E02", "E03", "E04", "E05", "E15", "E17", "E18", "E19"];
const PRESET_LABEL = { normal: "NORMAL NIGHTLY SYNC", downgrade: "CLIENT DOWNGRADE + COVER-UP", rogue: "ROGUE AGENT ON VENDOR LINK", canary: "CANARY TRIPWIRE HIT" };
const PRECEDENTS = [
  ["MIDNIGHT BLIZZARD · 2024 / CLOUDFLARE · 2023", "Credential hygiene", "Orphaned credentials and legacy secrets map to E04 gaps.", "Short-lived tokens, ownership reviews, and a deterministic canary."],
  ["SNOWFLAKE CUSTOMER BREACHES · 2024", "Service credentials", "Compromised service credentials and bulk exports map to TallyBridge risk.", "Behavioral fingerprints and export-volume checks."],
  ["TARGET · 2013 / SISENSE · 2024", "Third-party access", "Trusted vendor paths can become an entry path when controls rely on location.", "Request-level authentication and intent validation."],
  ["MICROSOFT EXCHANGE STORM-0558 · 2023", "Forensic visibility", "Logging and telemetry gaps can constrain reconstruction.", "Retention, clock integrity, and source-IP collection."],
];

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
  return response.json();
}
function Card({ title, eyebrow, children, className = "" }) { return <section className={`panel ${className}`}><div className="panel-head"><div><small>{eyebrow}</small><h2>{title}</h2></div></div>{children}</section>; }
function Metric({ label, value, icon: Icon, tone = "cyan" }) { return <div className="metric"><span className={`metric-icon ${tone}`}><Icon size={16}/></span><div><small>{label}</small><strong>{value ?? "—"}</strong></div></div>; }
function StatePill({ children, tone = "cyan", title }) { return <span className={`pill ${tone}`} title={title}><i/>{children}</span>; }

export default function App() {
  const [section, setSection] = useState(0);
  const [health, setHealth] = useState(null);
  const [topology, setTopology] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [normalized, setNormalized] = useState(true);
  const [tolerance, setTolerance] = useState(900);
  const [driftAssessment, setDriftAssessment] = useState(null);
  const [history, setHistory] = useState([]);
  const [result, setResult] = useState(null);
  const [presets, setPresets] = useState({});
  const [selectedCredential, setSelectedCredential] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [now, setNow] = useState(new Date());
  const [form, setForm] = useState({ key_id: "key-tb-07", system: "LedgerOne", endpoint: "/vendors/sync", user_agent: "TallyBridge-Sync 3.5.0", caller_ip: "10.20.4.18", timestamp: "", sync_window: "expected", request_volume: 18, export_volume: 4, e02_receipt: "present", e15_receipt: "present", action_sequence: "nightly_sync", request_id: "" });
  const [validation, setValidation] = useState({ true_positives: 0, false_positives: 0, missed_detections: 0, evidence_row_ids: [], metadata: {} });
  const [references, setReferences] = useState(Object.fromEntries(REFS.map(id => [id, ""])));
  const [checklist, setChecklist] = useState({});
  const [hashes, setHashes] = useState({});

  const refresh = async () => {
    setError("");
    try {
      const h = await api("/health");
      setHealth(h);
      const [t, e, hist, val, refs, checks, presetData] = await Promise.all([
        api("/topology"), api(`/timeline?normalized=${normalized}&tolerance_s=${tolerance}&limit=1000`), api("/engine/history"), api("/validation"), api("/evidence-references"), api("/checklist"), api("/engine/presets")
      ]);
      setTopology(t); setTimeline(e.events || []); setDriftAssessment(e.drift_assessment); setHistory(hist.evaluations || []); setValidation(val); setPresets(presetData.presets || {});
      setReferences(Object.fromEntries(REFS.map(id => [id, refs.references.find(row => row.evidence_id === id)?.row_reference || ""])));
      setChecklist(Object.fromEntries(checks.items.map(row => [row.item_id, Boolean(row.checked)])));
    } catch (err) { setError(`API unavailable: ${err.message}`); }
  };
  useEffect(() => { refresh(); const timer = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(timer); }, [normalized, tolerance]);
  const verdictData = useMemo(() => ["PASS", "QUARANTINE", "CRITICAL_CANARY"].map(verdict => ({ verdict, count: history.filter(row => row.verdict === verdict).length })), [history]);
  const volumeData = useMemo(() => {
    const groups = {};
    timeline.filter(row => ["E01", "E18"].includes(row.evidence_id)).forEach(row => { const day = (row.timestamp || "").slice(0, 10) || "unknown"; groups[day] ||= { day: day.slice(5), baseline: 0, observed: 0 }; groups[day][row.evidence_id === "E01" ? "baseline" : "observed"] += 1; });
    return Object.values(groups).slice(-12);
  }, [timeline]);
  const factors = result ? Object.entries(result.factors).map(([factor, score]) => ({ factor, score })) : [];
  const gateStatus = health?.request_gate || {};
  const setField = (key, value) => setForm(previous => ({ ...previous, [key]: value }));
  const applyPreset = key => { const preset = presets[key]; if (preset) { setForm({ ...preset, timestamp: "", action_sequence: (preset.action_sequence || []).join(", ") }); setResult(null); } };
  const execute = async event => {
    event.preventDefault(); setBusy(true); setError("");
    try { const body = { ...form, request_volume: Number(form.request_volume), export_volume: Number(form.export_volume), action_sequence: form.action_sequence.split(",").map(x => x.trim()).filter(Boolean), timestamp: form.timestamp || new Date().toISOString() }; const answer = await api("/engine/evaluate", { method: "POST", body: JSON.stringify(body) }); setResult(answer); const h = await api("/engine/history"); setHistory(h.evaluations || []); if (answer.canary) { setToast("Critical canary event saved"); setTimeout(() => setToast(""), 3500); } }
    catch (err) { setError(err.message); } finally { setBusy(false); }
  };
  const copyDecision = async () => { if (!result) return; try { await navigator.clipboard.writeText(JSON.stringify(result, null, 2)); setToast("Decision JSON copied"); setTimeout(() => setToast(""), 2200); } catch { setError("Clipboard access is unavailable in this browser context."); } };
  const saveValidation = async event => { event.preventDefault(); try { const saved = await api("/validation", { method: "POST", body: JSON.stringify(validation) }); setValidation(saved); setToast("Validation values saved"); setTimeout(() => setToast(""), 2200); } catch (err) { setError(err.message); } };
  const saveRefs = async () => { try { await api("/evidence-references", { method: "POST", body: JSON.stringify({ references }) }); setToast("Evidence references saved"); setTimeout(() => setToast(""), 2200); } catch (err) { setError(err.message); } };
  const toggleCheck = async (id, checked) => { setChecklist(prev => ({ ...prev, [id]: checked })); try { await api("/checklist", { method: "POST", body: JSON.stringify({ item_id: id, checked }) }); } catch (err) { setError(err.message); } };
  const hashEvidence = async evidence_id => { try { const result = await api("/evidence/hash", { method: "POST", body: JSON.stringify({ evidence_id }) }); setHashes(prev => ({ ...prev, [evidence_id]: result })); setToast(`${evidence_id} SHA-256 recorded in audit log`); setTimeout(() => setToast(""), 3000); } catch (err) { setError(err.message); } };

  return <div className="app">
    <header className="topbar">
      <div className="nav-brand-group"><a className="brand" href="/" aria-label="Orbit overview"><img src="/assets/solace-flower.png" alt=""/><span>orbit<span className="brand-dot">.</span></span></a><div className="case-label"><b>CR-26-047</b><span>HARBOR &amp; FINCH FREIGHT</span></div></div>
      <nav className="section-nav" aria-label="Defense console sections">{NAV.map((item, index) => <button key={item} className={section === index ? "active" : ""} onClick={() => setSection(index)}><small>0{index + 1}</small>{item}</button>)}</nav>
      <div className="system-status"><StatePill tone={health?.status === "ok" ? "green" : "amber"}>API {health?.status === "ok" ? "ONLINE" : "CHECK"}</StatePill><StatePill tone={gateStatus.can_forward ? "green" : "amber"} title="QBO’s Vendor API did not save the Bill Pay bank fields in this sandbox. Finance must save them in the QBO vendor screen.">{gateStatus.can_forward ? "Bank updates connected" : gateStatus.write_mode === "manual_qbo_ui" ? "Save bank details in QBO" : gateStatus.configured ? "Holds requests only" : "Bank gate off"}</StatePill><StatePill tone={health?.database_connected ? "green" : "amber"}>{health?.database_provider || "DATABASE"}</StatePill><span className="utc-clock"><Clock3 size={14}/>{now.toISOString().replace("T", " ").slice(0, 19)} UTC</span></div>
    </header>
    <div className="subhead"><div><span className="live-dot"/> DEFENSE CONSOLE <span className="subdivider">/</span> EVIDENCE-LED OPERATIONS</div><span>LAST SYNC {health?.last_sync_utc || "—"}</span></div>
    {error && <div className="error-banner"><AlertTriangle size={16}/>{error}<button onClick={refresh}>Retry</button></div>}
    <main className="workspace"><AnimatePresence mode="wait"><motion.div key={section} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} transition={{ duration: .2 }}>
      {section === 0 && <TopologyView topology={topology} eventCount={timeline.length} selected={selectedCredential} onSelect={setSelectedCredential} />}
      {section === 1 && <ClockView normalized={normalized} setNormalized={setNormalized} timeline={timeline} tolerance={tolerance} setTolerance={setTolerance} driftAssessment={driftAssessment} />}
      {section === 2 && <EngineView presets={presets} applyPreset={applyPreset} form={form} setField={setField} execute={execute} busy={busy} result={result} copyDecision={copyDecision} factors={factors} history={history} verdictData={verdictData} volumeData={volumeData} />}
      {section === 3 && <HardeningView />}
      {section === 4 && <ValidationView validation={validation} setValidation={setValidation} saveValidation={saveValidation} refs={references} setRefs={setReferences} saveRefs={saveRefs} checklist={checklist} toggleCheck={toggleCheck} hashes={hashes} hashEvidence={hashEvidence} />}
    </motion.div></AnimatePresence></main>
    <footer className="footer"><span>ORBIT · CR-26-047</span><span>LOCAL DEMONSTRATION · SIMULATIONS DO NOT ENFORCE PRODUCTION REQUESTS</span><span>UTC {now.toISOString().slice(11, 19)}</span></footer>
    <AnimatePresence>{toast && <motion.div className="toast" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>{toast}</motion.div>}</AnimatePresence>
  </div>;
}

function TopologyView({ topology, eventCount, selected, onSelect }) {
  const credentials = topology?.credentials || [];
  return <div className="page-grid">
    <div className="page-intro"><div><small>ORBIT · CR-26-047 VENDOR CHANGE DEFENSE</small><h1>Stop risky vendor bank changes<br/><em>before payment.</em></h1><p className="purpose-copy">Orbit checks identity, vendor scope, and separate Finance approval before a bank change can move forward.</p></div><div className="intro-art" aria-hidden="true"><img src="/assets/solace-flower.png" alt=""/></div><StatePill tone="amber">{topology?.blind_spots?.length || 0} EVIDENCE GAPS</StatePill></div>
    <div className="gate-journey"><div className="gate-journey-title"><small>QBO SANDBOX BANK-CHANGE PATH</small><span>Vendor API did not save Bill Pay ACH in our sandbox check.</span></div><div className="gate-steps">{["Request held", "Finance approves", "Save ACH in QBO", "Confirm in Orbit"].map((step, index) => <div key={step}><b>0{index + 1}</b><span>{step}</span></div>)}</div></div>
    <div className="two-col topology-grid">
      <Card title="Cross-system topology" eyebrow="LIVE MODEL · CASE EVIDENCE">
        <div className="topology-canvas"><svg viewBox="0 0 820 410" role="img" aria-label="Finance and integration topology">
          <rect x="20" y="26" width="780" height="345" rx="18" className="net-boundary"/><text x="38" y="50" className="svg-label">VENDOR PRIVATE LINK · 10.20.4.0/24 · LOCATION ALONE IS NOT TRUST</text>
          <path d="M180 155 C290 90 360 90 450 155" className="flow cyan"/><path d="M450 155 C545 215 560 210 640 160" className="flow blue"/><path d="M178 165 C260 280 400 300 620 185" className="flow amber-flow"/><path d="M160 180 C145 275 260 320 345 320" className="flow red-flow"/>
          <TopologyNode x={120} y={120} title="LedgerOne" tag="FINANCE · E01 / E18 / E19" color="cyan"/><TopologyNode x={395} y={120} title="TallyBridge" tag="NIGHTLY CONNECTOR" color="blue"/><TopologyNode x={620} y={120} title="HelpDeskr" tag="SUPPORT · E02" color="cyan"/><TopologyNode x={620} y={280} title="BlueVault" tag="FILE STORE · E05 CLOCK UNCERTAIN" color="amber"/><TopologyNode x={120} y={280} title="SSO" tag="STAFF AUTH ONLY · E03" color="blue"/>
          <text x="337" y="217" className="svg-note">REQUEST / RECEIPT CORRELATION</text><text x="38" y="354" className="svg-label">OFFICE / SERVERS · 172.16.0.0/16</text>
        </svg></div>
        <div className="network-note"><ShieldAlert size={18}/><div><b>TRUSTED NETWORK ≠ TRUSTED REQUEST</b><span>A private-link address can establish route context. It cannot prove identity, intent, or permission for a bank-field change.</span></div></div>
      </Card>
      <div className="stack">
        <Card title="Credential risk register" eyebrow="E04 · CLICK TO INSPECT">
          <div className="credential-list">{credentials.map(item => <button className={`credential ${selected?.credential_id === item.credential_id ? "selected" : ""}`} key={item.credential_id} onClick={() => onSelect(item)}><span className="credential-icon"><Fingerprint size={17}/></span><span><b>{item.credential_id}</b><small>{item.integration || item.system || "Unassigned"} · {item.scope || "scope unknown"}</small></span><StatePill tone={item.credential_id.includes("03") ? "red" : "amber"}>{item.credential_id.includes("03") ? "CANARY" : "REVIEW"}</StatePill></button>)}</div>
          <AnimatePresence>{selected && <motion.div className="credential-detail" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}><b>{selected.credential_id}</b><div><span>Owner</span><code>{selected.owner || "UNKNOWN"}</code></div><div><span>Scope</span><code>{selected.scope || "UNKNOWN"}</code></div><div><span>Expiry</span><code>{selected.token_lifetime ? `${selected.token_lifetime}s` : "NONE RECORDED"}</code></div><div><span>IP restriction</span><code>{selected.ip_restricted ? "PRESENT" : "NONE RECORDED"}</code></div><p>{selected.credential_id.includes("03") ? "Deterministic tripwire: any attributed use creates a CRITICAL_CANARY alert." : "Restrict endpoint scope, set expiry, and verify ownership while preserving legitimate nightly operations."}</p></motion.div>}</AnimatePresence>
        </Card>
        <Card title="Known visibility gaps" eyebrow="EVIDENCE LIMITS"><ul className="blind-list">{(topology?.blind_spots || []).map(item => <li key={item}><CircleHelp size={14}/>{item}</li>)}</ul></Card>
      </div>
    </div>
    <div className="metric-row"><Metric label="Loaded event rows" value={eventCount} icon={Activity}/><Metric label="Documented network ranges" value={topology?.network_ranges?.length || 0} icon={Network}/><Metric label="Credential tripwire" value="key-tb-03" icon={Siren} tone="red"/><Metric label="Integration path" value="LedgerOne ↔ HelpDeskr" icon={Waypoints}/></div>
  </div>;
}
function TopologyNode({ x, y, title, tag, color }) { return <g className={`topo-node ${color}`}><circle cx={x} cy={y} r="49"/><circle cx={x} cy={y} r="39"/><text x={x} y={y - 3} textAnchor="middle" className="node-name">{title}</text><text x={x} y={y + 15} textAnchor="middle" className="node-tag">{tag}</text></g>; }

function ClockView({ normalized, setNormalized, timeline, tolerance, setTolerance, driftAssessment }) {
  const relevant = timeline.filter(row => ["E01", "E02", "E05", "E15", "E18", "E19"].includes(row.evidence_id)).slice(0, 60);
  return <div className="page-grid"><div className="page-intro"><div><small>02 / DRIFT-AWARE TIMELINE</small><h1>Put events in order.<br/><em>Keep uncertainty visible.</em></h1></div><StatePill tone="amber">E05 ORDER UNVERIFIED</StatePill></div>
    <Card title="Forensic event timeline" eyebrow="SOURCE EVENTS · ORIGINAL VALUES PRESERVED">
      <div className="toggle-row"><div><button className={normalized ? "selected" : ""} onClick={() => setNormalized(true)}>NORMALIZED UTC</button><button className={!normalized ? "selected" : ""} onClick={() => setNormalized(false)}>RAW UNALIGNED LOGS</button></div><span><FileClock size={15}/>{relevant.length} loaded rows</span></div>
      <div className="drift-callout"><Clock3 size={18}/><p><b>BlueVault clock assessment: {driftAssessment?.verdict || "loading"}.</b> The model will only align E05 if the evidence can identify an offset. Otherwise, raw epoch values remain unaligned with a visible uncertainty band. Missing source-IP values remain UNKNOWN.</p><label>TOLERANCE <select value={tolerance} onChange={e => setTolerance(Number(e.target.value))}><option value="300">±5 MIN</option><option value="900">±15 MIN</option><option value="1800">±30 MIN</option><option value="3600">±60 MIN</option></select></label></div>
      <div className="table-wrap"><table><thead><tr><th>UTC / SOURCE TIME</th><th>STREAM</th><th>SYSTEM</th><th>KEY / REQUEST</th><th>CALLER IP</th><th>USER-AGENT / ACTION</th><th>CORRELATION</th></tr></thead><tbody>{relevant.map(row => <tr key={`${row.evidence_id}-${row.id}`} className={row.evidence_id === "E05" ? "uncertain-row" : ""}><td><code>{row.timestamp || row.original_timestamp}</code>{row.evidence_id === "E05" && <small className="uncertainty">±{row.uncertainty?.tolerance_s}s · {row.clock_status}</small>}</td><td><span className={`evidence-chip ${row.evidence_id === "E05" ? "amber" : ""}`}>{row.evidence_id}</span></td><td>{row.system}</td><td><code>{row.api_key_id || row.correlation?.request_id || "UNKNOWN"}</code></td><td><code>{row.source_ip || "UNKNOWN"}</code></td><td>{row.user_agent || row.action || "UNRESOLVED"}</td><td><span className="corr">{row.clock_status === "ALIGNED" ? "CLOCK ALIGNED" : "UNVERIFIED"}</span></td></tr>)}</tbody></table></div>
    </Card>
    <div className="two-col"><Card title="Four-key join pipeline" eyebrow="CORRELATION REQUIREMENTS"><div className="join-flow">{["Request ID", "Key ID", "Caller IP", "User-Agent"].map((value, i) => <div key={value}><code>0{i + 1}</code><b>{value}</b>{i < 3 && <span>+</span>}</div>)}</div><p className="muted">Missing fields remain unresolved. Similar timestamps alone do not establish that two events belong to one request.</p></Card><Card title="Telemetry remediation" eyebrow="CONTROL PLAN"><ul className="plan-list">{["Extend E01 retention to 180+ days", "Enable immutable centralized logging", "Enable source-IP logging on E05", "Synchronize system clocks through NTP", "Capture daily E04 credential snapshots"].map(item => <li key={item}><Check size={14}/>{item}</li>)}</ul><p className="muted">Storm-0558 illustrates why log retention and provenance matter to incident reconstruction. This is a control mapping, not a claim that the incident used Orbit controls.</p></Card></div>
  </div>;
}

function EngineView({ presets, applyPreset, form, setField, execute, busy, result, copyDecision, factors, history, verdictData, volumeData }) {
  return <div className="page-grid"><div className="page-intro"><div><small>03 / TWIN-PROOF &amp; FOUR-FACTOR ENGINE</small><h1>Evaluate the request.<br/><em>Corroborate the evidence.</em></h1></div><StatePill tone="cyan"><Radio size={12}/> SIMULATION READY</StatePill></div>
    <div className="preset-row">{Object.keys(PRESET_LABEL).map(key => <button key={key} className={`preset ${key === "canary" ? "critical" : ""}`} onClick={() => applyPreset(key)}><small>PRESET 0{Object.keys(PRESET_LABEL).indexOf(key) + 1}</small><b>{PRESET_LABEL[key]}</b><ArrowDownRight size={15}/></button>)}</div>
    <div className="two-col engine-layout"><Card title="Request simulation" eyebrow="CUSTOM PAYLOAD · POST /API/ENGINE/EVALUATE">
      <form className="sim-form" onSubmit={execute}><label>Key ID<input value={form.key_id} onChange={e => setField("key_id", e.target.value)}/></label><label>User-Agent<input value={form.user_agent} onChange={e => setField("user_agent", e.target.value)}/></label><label>Caller IP<input value={form.caller_ip || ""} onChange={e => setField("caller_ip", e.target.value)}/></label><label>System<select value={form.system} onChange={e => setField("system", e.target.value)}><option>LedgerOne</option><option>HelpDeskr</option><option>BlueVault</option><option>SSO</option></select></label><label>Endpoint<input value={form.endpoint} onChange={e => setField("endpoint", e.target.value)}/></label><label>Request volume<input type="number" min="0" max="1000000" value={form.request_volume} onChange={e => setField("request_volume", e.target.value)}/></label><label>Export volume<input type="number" min="0" max="1000000" value={form.export_volume} onChange={e => setField("export_volume", e.target.value)}/></label><label>Sync window<select value={form.sync_window} onChange={e => setField("sync_window", e.target.value)}><option value="expected">Expected</option><option value="outside">Outside</option><option value="unknown">Unknown</option></select></label><label>E02 receipt<select value={form.e02_receipt} onChange={e => setField("e02_receipt", e.target.value)}><option value="present">Present</option><option value="missing">Missing</option><option value="unknown">Unknown</option></select></label><label>E15 receipt<select value={form.e15_receipt} onChange={e => setField("e15_receipt", e.target.value)}><option value="present">Present</option><option value="missing">Missing</option><option value="unknown">Unknown</option></select></label><label>Event ID<input value={form.event_id || ""} onChange={e => setField("event_id", e.target.value)}/></label><label>Request ID<input value={form.request_id} onChange={e => setField("request_id", e.target.value)}/></label><label className="wide-field">Timestamp · local entry converted to UTC<input type="datetime-local" value={form.timestamp ? new Date(form.timestamp).toISOString().slice(0,16) : ""} onChange={e => setField("timestamp", e.target.value ? new Date(e.target.value).toISOString() : "")}/></label><label className="wide-field">Action sequence<input value={form.action_sequence} onChange={e => setField("action_sequence", e.target.value)} placeholder="Create Job, Download, Delete Job"/></label><button className="execute-button" disabled={busy}>{busy ? "EVALUATING…" : "EXECUTE SIMULATION"}<ArrowRight size={16}/></button></form>
      <div className="no-write"><ShieldCheck size={15}/> SIMULATED · NO LIVE WRITE OR EXTERNAL ACTION</div>
    </Card>
    <div className="stack"><Card title="Decision" eyebrow="ENGINE RESPONSE"><div className={`verdict-panel ${result?.verdict?.toLowerCase() || "empty"}`}><div className="verdict-top"><span className="verdict-icon">{result?.verdict === "PASS" ? <ShieldCheck/> : result?.verdict === "CRITICAL_CANARY" ? <Siren/> : <ShieldAlert/>}</span><div><small>ACTUAL API VERDICT</small><strong>{result?.verdict || "AWAITING INPUT"}</strong></div><b className="score">{result ? result.risk_score : "—"}<small>/100</small></b></div>{result && <><p>{result.recommended_response}</p><div className="factor-list">{factors.map(f => <div key={f.factor}><span>{f.factor.replaceAll("_", " ")}</span><div className="factor-track"><i style={{ width: `${f.score}%` }}/></div><code>{f.score}</code></div>)}</div><div className="twin-status"><span>TWIN-PROOF</span><b>{result.twin_proof.status.toUpperCase()}</b>{result.twin_proof.missing.length > 0 && <small>Missing: {result.twin_proof.missing.join(", ")}</small>}</div><ul className="reason-list">{result.reasons.map(reason => <li key={reason}>{reason}</li>)}</ul><small className="limitations">{result.limitations.join(" ")}</small><button className="secondary-button copy-result" onClick={copyDecision}><Copy size={13}/> COPY DECISION JSON</button></>}</div></Card>
    </div></div>
      <Suspense fallback={<div className="chart-empty">Loading investigation charts…</div>}><EngineCharts result={result} factors={factors} verdictData={verdictData} volumeData={volumeData}/></Suspense>
    <Card title="Evaluation history" eyebrow="PERSISTED · MOST RECENT FIRST"><div className="table-wrap"><table><thead><tr><th>TIME UTC</th><th>KEY</th><th>USER-AGENT</th><th>CALLER IP</th><th>VERDICT</th><th>SCORE</th><th>RULES</th></tr></thead><tbody>{history.map(row => <tr key={row.evaluation_id}><td><code>{row.timestamp}</code></td><td><code>{row.key_id}</code></td><td>{row.user_agent || "UNKNOWN"}</td><td><code>{row.caller_ip || "UNKNOWN"}</code></td><td><StatePill tone={row.verdict === "PASS" ? "green" : row.verdict === "CRITICAL_CANARY" ? "red" : "amber"}>{row.verdict}</StatePill></td><td>{row.risk_score}</td><td>{row.triggered_rules.join(", ") || "—"}</td></tr>)}</tbody></table></div>{!history.length && <p className="muted">No simulations persisted yet.</p>}</Card>
  </div>;
}

function HardeningView() {
  const rows = [["CREDENTIALS", "Immortal keys · broad privileges · active legacy key", "Short-lived tokens · endpoint scopes · legacy key as zero-data canary"], ["NETWORK", "Blind vendor IP allowlisting · implicit network trust", "Request-level identity, intent, and behavior checks · no trust by subnet alone"], ["TELEMETRY", "90-day E01 retention · missing E05 IP · clock drift", "180+ day immutable logs · source-IP capture · NTP · daily E04 snapshots"], ["PAYMENT APPROVAL", "Bank changes without independent approval reference", "Mandatory E18/E19 approval refs · independent verification · separation of duties"]];
  return <div className="page-grid"><div className="page-intro"><div><small>04 / HARDENING &amp; RESPONSE</small><h1>Turn evidence gaps<br/><em>into durable controls.</em></h1></div><StatePill tone="red"><Siren size={12}/> CANARY TRIPWIRE ACTIVE</StatePill></div>
    <Card title="Before / after control matrix" eyebrow="DEFENSE ROADMAP"><div className="matrix">{rows.map(([name, before, after]) => <div className="matrix-row" key={name}><b>{name}</b><div className="before"><small>BEFORE</small>{before}</div><div className="after"><small>AFTER</small>{after}</div></div>)}</div></Card>
    <div className="two-col"><Card title="Legacy key canary" eyebrow="KEY-TB-03 · ANY USE = CRITICAL"><div className="canary-flow">{["key-tb-03 (legacy)", "Any API attempt", "Canary detection", "Immediate alert", "Isolated alert sink", "Security investigation"].map((step, i) => <div key={step} className={i === 0 ? "critical-step" : ""}><code>0{i + 1}</code><b>{step}</b>{i < 5 && <ArrowRight size={15}/>}</div>)}</div><p className="muted">The canary is a deterministic identifier tripwire. It contains no real data access. Classification assumes correct key attribution.</p></Card><Card title="Four-layer defense architecture" eyebrow="INTERLOCKED CONTROLS"><div className="layers">{[["01", "TELEMETRY & CLOCK INTEGRITY", "UTC · drift bounds · immutable retention"], ["02", "IDENTITY & SECRET HARDENING", "Short-lived tokens · least privilege · canary"], ["03", "REAL-TIME DETECTION", "Twin-proof · fingerprint · volume anomalies"], ["04", "OPERATIONAL & FORENSIC DISCIPLINE", "Evidence snapshots · hashes · uncertainty"]].map(([number, title, detail]) => <div key={number}><code>{number}</code><span><b>{title}</b><small>{detail}</small></span><ChevronRight size={15}/></div>)}</div></Card></div>
    <Card title="Documented precedents · control mappings" eyebrow="FACTS AND PROPOSED MAPPINGS ARE SEPARATED"><div className="precedents">{PRECEDENTS.map(([title, theme, fact, control]) => <article key={title}><small>{theme}</small><h3>{title}</h3><p><b>Incident lesson</b>{fact}</p><p><b>Proposed mapping</b>{control}</p><span>Control mapping only · not a claim of deployment</span></article>)}</div></Card>
  </div>;
}

function ValidationView({ validation, setValidation, saveValidation, refs, setRefs, saveRefs, checklist, toggleCheck, hashes, hashEvidence }) {
  return <div className="page-grid"><div className="page-intro"><div><small>05 / VALIDATION &amp; UNCERTAINTY</small><h1>Measure what you know.<br/><em>Label what you don’t.</em></h1></div><StatePill tone="amber">DEMO INPUTS · NOT BENCHMARKS</StatePill></div>
    <div className="two-col"><Card title="Detection metrics" eyebrow="EDITABLE · PERSISTED IN BACKEND"><form className="sim-form validation-form" onSubmit={saveValidation}>{[["true_positives", "True positives"], ["false_positives", "False positives"], ["missed_detections", "Missed detections"]].map(([key,label]) => <label key={key}>{label}<input type="number" min="0" value={validation[key] ?? 0} onChange={e => setValidation(v => ({ ...v, [key]: Number(e.target.value) }))}/></label>)}<label className="wide-field">Evidence row IDs · comma separated<input value={(validation.evidence_row_ids || []).join(", ")} onChange={e => setValidation(v => ({ ...v, evidence_row_ids: e.target.value.split(",").map(x=>x.trim()).filter(Boolean) }))}/></label><button className="execute-button">SAVE VALIDATION<Check size={16}/></button></form><div className="score-cards"><Metric label="Precision" value={`${Math.round((validation.precision || 0) * 100)}%`} icon={ShieldCheck} tone="green"/><Metric label="Recall" value={`${Math.round((validation.recall || 0) * 100)}%`} icon={Activity}/><Metric label="F1" value={`${Math.round((validation.f1 || 0) * 100)}%`} icon={Fingerprint} tone="amber"/></div><p className="muted">{validation.performance_label || "Entered values are demonstration data, not experimentally validated."}</p></Card>
      <Card title="Evidence-first checklist" eyebrow="STATE SAVED TO BACKEND"><div className="checklist">{CHECKS.map(item => <label key={item}><input type="checkbox" checked={Boolean(checklist[item])} onChange={e => toggleCheck(item, e.target.checked)}/><span>{item}</span><small>{item.includes("Hash") ? "No file hash asserted" : "PENDING / RECORDED"}</small></label>)}</div></Card></div>
    <Card title="Case evidence row references" eyebrow="EDITABLE · STORED PERSISTENTLY"><div className="refs-grid">{REFS.map(id => <label key={id}><code>{id}</code><input value={refs[id] || ""} placeholder="Insert Case Row ID" onChange={e => setRefs(prev => ({ ...prev, [id]: e.target.value }))}/></label>)}</div><button className="secondary-button" onClick={saveRefs}>SAVE REFERENCES <Check size={14}/></button><div className="hash-list"><b>FILE INTEGRITY · SHA-256</b>{REFS.map(id => <div key={id}><code>{id}</code>{hashes[id] ? <code className="hash-value">{hashes[id].sha256}</code> : <span>No hash recorded this session</span>}<button className="secondary-button" onClick={() => hashEvidence(id)}>HASH SOURCE FILE</button></div>)}</div></Card>
    <Card title="Uncertainty ledger" eyebrow="EVIDENCE · GAP · RESOLUTION"><div className="uncertainty-ledger"><div className="ledger-head"><b>KNOWN</b><b>UNKNOWN / GAPS</b><b>WHAT WOULD SETTLE IT</b></div>{[["E01", "UTC logs; 90-day retention cutoff.", "Earlier rows may no longer exist.", "Recover archived logs and immutable backups."], ["E05", "Unsynchronized Unix timestamps.", "Exact offset unknown; source IPs missing.", "Recover source telemetry, NTP data, and independent flows."], ["E04", "Current credential state only.", "Historical owners, scopes, and changes unknown.", "Recover credential snapshots and identity records."], ["E17", "Indicator list was supplied.", "Completeness is not established.", "Obtain full export and validate provenance."], ["E18/E19", "API and vendor-change records exist.", "Independent approval evidence may be incomplete.", "Recover approval records and correlate modification IDs."]].map(([id,known,gap,resolve])=><div className="ledger-row" key={id}><code>{id}</code><span>{known}</span><span>{gap}</span><span>{resolve}</span></div>)}</div></Card>
  </div>;
}
