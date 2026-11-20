import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

function Panel({ title, eyebrow, children }) {
  return <section className="panel"><div className="panel-head"><div><small>{eyebrow}</small><h2>{title}</h2></div></div>{children}</section>;
}

export default function EngineCharts({ result, factors, verdictData, volumeData }) {
  return <>
    <div className="two-col">
      <Panel title="Four-factor risk profile" eyebrow="SCORED REQUEST"><div className="chart-box short">{result ? <ResponsiveContainer><BarChart data={factors}><CartesianGrid strokeDasharray="3 3" stroke="#243247"/><XAxis dataKey="factor" tick={{ fill: "#94a3b8", fontSize: 10 }}/><YAxis domain={[0, 35]} tick={{ fill: "#94a3b8", fontSize: 10 }}/><Tooltip contentStyle={{ background: "#101827", border: "1px solid #243247" }}/><Bar dataKey="score" fill="#00e5ff" radius={[4,4,0,0]} isAnimationActive/></BarChart></ResponsiveContainer> : <div className="chart-empty">Run a simulation to chart its actual factor scores.</div>}</div></Panel>
      <Panel title="Persisted verdict distribution" eyebrow="SAVED EVALUATIONS"><div className="chart-box"><ResponsiveContainer><PieChart><Pie data={verdictData} dataKey="count" nameKey="verdict" innerRadius="52%" outerRadius="78%" paddingAngle={3} isAnimationActive>{verdictData.map((row, i) => <Cell key={row.verdict} fill={["#00d68f", "#ffb020", "#ff304f"][i]}/>)}</Pie><Tooltip contentStyle={{ background: "#101827", border: "1px solid #243247" }}/><Legend/></PieChart></ResponsiveContainer></div></Panel>
    </div>
    <Panel title="E01 reference vs E18 observed request volume" eyebrow="ACTUAL EVENT COUNTS · SOURCE STREAMS"><div className="chart-box">{volumeData.length ? <ResponsiveContainer><LineChart data={volumeData}><CartesianGrid strokeDasharray="3 3" stroke="#243247"/><XAxis dataKey="day" tick={{ fill: "#94a3b8", fontSize: 10 }}/><YAxis tick={{ fill: "#94a3b8", fontSize: 10 }}/><Tooltip contentStyle={{ background: "#101827", border: "1px solid #243247" }}/><Legend/><Line name="E01 reference" dataKey="baseline" stroke="#1677ff" strokeWidth={2} dot={{ r: 2 }} isAnimationActive/><Line name="E18 observed" dataKey="observed" stroke="#00e5ff" strokeWidth={2} dot={{ r: 2 }} isAnimationActive/></LineChart></ResponsiveContainer> : <div className="chart-empty">No event data returned.</div>}</div></Panel>
  </>;
}
