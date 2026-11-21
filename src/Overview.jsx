import React, { useState } from 'react';
import {
  ResponsiveContainer, AreaChart, Area, CartesianGrid, XAxis, YAxis, Tooltip,
  BarChart, Bar, PieChart, Pie, Cell
} from 'recharts';
import {
  Activity, ScanLine, AlertTriangle, ShieldAlert, ChartNoAxesCombined,
  ArrowUpRight, ArrowRight, ShieldCheck, Layers3, Database, Play, Upload,
  BookOpen, Server, LockKeyhole, CheckCircle2, CircleAlert
} from 'lucide-react';

function ChartTip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tip"><small>{label}</small>{payload.map((item, index) =>
    <div key={index}><i style={{ background: item.color }} />{item.name}: <b>{item.value}</b></div>
  )}</div>;
}

function Metric({ label, value, sub, icon: Icon, tone = 'mint' }) {
  return <article className={'metric metric-' + tone}>
    <div className="metric-head"><span>{label}</span><span className="metric-icon"><Icon size={17}/></span></div>
    <div className="metric-number">{Number(value || 0).toLocaleString()}</div>
    <div className="metric-foot"><span>{sub}</span></div>
  </article>;
}

function ProviderStatus({ provider, onManage }) {
  const configured = Boolean(provider?.configured);
  const connected = provider?.status === 'connected';
  const enabled = Boolean(provider?.enabled);
  const label = connected ? 'Connected' : configured ? (provider?.status || 'Configured') : 'Not configured';
  return <article className="readiness-provider">
    <span className={'readiness-indicator ' + (connected ? 'is-connected' : configured ? 'is-pending' : '')}/>
    <div className="readiness-provider-copy">
      <b>{provider?.id === 'aws' ? 'Amazon Web Services' : 'Microsoft Azure'}</b>
      <small>{label}{enabled ? ' · collection enabled' : ' · collection paused'}</small>
    </div>
    <button type="button" className="readiness-link" onClick={onManage}>Manage <ArrowUpRight size={13}/></button>
  </article>;
}

function Empty({ icon: Icon = Database, title = 'Nothing here yet', desc = 'Import telemetry or run an offline simulation to populate this view.' }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={22}/></div><b>{title}</b><p>{desc}</p></div>;
}

export default function Overview({
  dashboard = {}, activity = [], severityData = [], topRules = [], incidents = [],
  sources = {}, onIncident, range, setRange, go, events = 0, IncidentTable,
  PALETTE = {}, onRunSimulation, onImport, scenario, setScenario, busy,
  providers = [], readiness = {}
}) {
  const aws = providers.find(item => item.id === 'aws') || { id: 'aws' };
  const azure = providers.find(item => item.id === 'azure') || { id: 'azure' };
  const workerHealthy = readiness?.ok === true || readiness?.worker === 'running' || readiness?.worker === 'healthy' || readiness?.worker === 'not_required';
  const workerLabel = readiness?.worker === 'not_required' ? 'Not required in local mode' : workerHealthy ? 'Worker healthy' : readiness?.worker || 'Status unavailable';
  const lastHeartbeat = readiness?.worker_heartbeat_at
    ? new Date(readiness.worker_heartbeat_at).toLocaleString()
    : 'No heartbeat reported';

  return <div className="overview">
    <section className="command-hero" aria-label="Cloud security workspace">
      <div className="command-hero-copy">
        <span className="command-hero-kicker"><i/> EVIDENCE-LED CLOUD DEFENSE <span> / </span> WORKSPACE 01</span>
        <h2>See the signal.<br/><em>Understand the risk.</em></h2>
        <p>Cloud telemetry, detection context and verifiable evidence — brought into one focused operations workspace.</p>
        <div className="command-hero-actions">
          <button className="button button-primary" onClick={() => go('incidents')}>Open incident queue <ArrowUpRight size={15}/></button>
          <button className="command-hero-secondary" onClick={() => go('data-sources')}>Manage cloud sources <ArrowRight size={14}/></button>
        </div>
        <div className="command-hero-stats">
          <div><b>{Number(dashboard.events_total || 0).toLocaleString()}</b><small>EVENTS OBSERVED</small></div>
          <span/>
          <div><b>{Number(dashboard.findings_total || 0).toLocaleString()}</b><small>DETECTION SIGNALS</small></div>
          <span/>
          <div><b>{Number(dashboard.incidents_total || 0).toLocaleString()}</b><small>INCIDENTS</small></div>
        </div>
      </div>
      <div className="command-hero-visual" aria-hidden="true">
        <div className="hero-grid-texture"/>
        <svg className="hero-network" viewBox="0 0 440 340" fill="none">
          <defs><linearGradient id="heroStroke" x1="68" y1="45" x2="365" y2="300"><stop stopColor="#a6f27a"/><stop offset="1" stopColor="#71c8f5"/></linearGradient><radialGradient id="heroGlow"><stop stopColor="#a6f27a" stopOpacity=".25"/><stop offset="1" stopColor="#a6f27a" stopOpacity="0"/></radialGradient></defs>
          <circle cx="242" cy="164" r="146" stroke="#8da8bd" strokeOpacity=".12" strokeDasharray="2 8"/>
          <circle cx="242" cy="164" r="112" stroke="#8da8bd" strokeOpacity=".2"/>
          <circle cx="242" cy="164" r="77" stroke="#8da8bd" strokeOpacity=".16" strokeDasharray="3 7"/>
          <circle cx="242" cy="164" r="54" fill="url(#heroGlow)"/>
          <path d="M89 223 151 172 201 196 245 116 306 139 367 76M151 172 166 89 245 116M201 196 218 268 306 241 367 76M245 116 306 241" stroke="url(#heroStroke)" strokeOpacity=".72" strokeWidth="1.4"/>
          <path d="M242 164 245 116M242 164 201 196M242 164 306 139" stroke="#d9f9c7" strokeOpacity=".4" strokeDasharray="3 5"/>
          <circle cx="242" cy="164" r="31" fill="#17291f" stroke="#a6f27a" strokeOpacity=".8"/>
          <path d="M242 143 258 149v12c0 9-6.5 15-16 19-9.5-4-16-10-16-19v-12l16-6Z" stroke="#c5f7a7" strokeWidth="1.5"/>
          <path d="m234 163 6 6 11-13" stroke="#c5f7a7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          <g fill="#a6f27a" stroke="#0e1a24" strokeWidth="4"><circle cx="89" cy="223" r="6"/><circle cx="151" cy="172" r="5"/><circle cx="166" cy="89" r="5"/><circle cx="201" cy="196" r="6"/><circle cx="245" cy="116" r="6"/><circle cx="306" cy="139" r="5"/><circle cx="306" cy="241" r="5"/></g>
          <circle cx="367" cy="76" r="7" fill="#71c8f5" stroke="#10202d" strokeWidth="4"/>
        </svg>
        <div className="hero-visual-caption"><span className="hero-caption-dot"/><span>TELEMETRY GRAPH</span><b>OBSERVED RELATIONSHIPS</b></div>
        <div className="hero-float-card hero-float-top"><span>COLLECTION</span><b>{providers.some(item => item.status === 'connected') ? 'Connected source' : 'Awaiting source'}</b></div>
        <div className="hero-float-card hero-float-bottom"><span>RESPONSE MODE</span><b><LockKeyhole size={12}/> Read-only by default</b></div>
      </div>
    </section>
    <SetupGuide providers={providers} events={dashboard.events_total} findings={dashboard.findings_total} go={go} onRunSimulation={onRunSimulation} onImport={onImport} busy={busy}/>
    <section className="readiness-panel" aria-label="Environment readiness">
      <div className="readiness-heading">
        <div><span className="overline">ENVIRONMENT STATUS</span><h2>Collection readiness</h2></div>
        <span className={'readiness-health ' + (workerHealthy ? 'healthy' : 'attention')}>
          {workerHealthy ? <CheckCircle2 size={14}/> : <CircleAlert size={14}/>}
          {workerLabel}
        </span>
      </div>
      <div className="readiness-grid">
        <ProviderStatus provider={aws} onManage={() => go('data-sources')}/>
        <ProviderStatus provider={azure} onManage={() => go('data-sources')}/>
        <article className="readiness-provider">
          <span className={'readiness-indicator ' + (workerHealthy ? 'is-connected' : 'is-pending')}/>
          <div className="readiness-provider-copy"><b>Scheduled collector</b><small>{lastHeartbeat}</small></div>
          <span className="readiness-static"><Server size={14}/> Local worker</span>
        </article>
        <article className="readiness-provider">
          <span className="readiness-indicator is-locked"/>
          <div className="readiness-provider-copy"><b>Cloud response actions</b><small>Disabled · approval and adapter review required</small></div>
          <span className="readiness-static"><LockKeyhole size={14}/> Read-only</span>
        </article>
      </div>
      <p className="readiness-footnote">Provider status reflects the configured workspace. Offline simulations do not contact cloud accounts.</p>
    </section>

    <div className="metric-grid">
      <Metric label="Events analyzed" value={dashboard.events_total} sub="Normalized audit records" icon={Activity}/>
      <Metric label="Detection findings" value={dashboard.findings_total} sub="Rule-matched signals" icon={ScanLine} tone="blue"/>
      <Metric label="Correlated incidents" value={dashboard.incidents_total} sub="Investigation candidates" icon={AlertTriangle} tone="amber"/>
      <Metric label="Critical incidents" value={dashboard.critical_incidents} sub="Require analyst review" icon={ShieldAlert} tone="rose"/>
    </div>

    {Number(dashboard.events_total || 0) === 0 && <section className="quickstart-panel">
      <div className="quickstart-copy"><span className="overline">WORKSPACE SETUP</span>
        <h2>Start with a verified telemetry workflow.</h2>
        <p>Import cloud audit records or run a labelled offline scenario. Simulations are local-only and make no AWS or Azure API calls.</p>
        <div className="quickstart-actions">
          <label className="quickstart-select"><span>SCENARIO</span><select value={scenario} onChange={event => setScenario(event.target.value)}>
            <option value="all">All scenarios</option><option value="multi-stage-compromise">Multi-stage compromise</option>
            <option value="iam-policy-escalation">IAM privilege escalation</option><option value="public-s3-policy">Public S3 policy</option>
            <option value="public-admin-ingress">Public admin ingress</option>
          </select></label>
          <button className="button button-primary" onClick={onRunSimulation} disabled={busy}><Play size={15} fill="currentColor"/>{busy ? 'Running…' : 'Run offline simulation'}</button>
          <button className="button button-soft" onClick={onImport}><Upload size={15}/>Import telemetry</button>
        </div>
      </div>
      <div className="quickstart-side">
        <div><b>01</b><span><strong>Collect or import</strong><small>CloudTrail, Security Hub and Azure Activity Log</small></span></div>
        <div><b>02</b><span><strong>Investigate findings</strong><small>Review severity, rationale and related events</small></span></div>
        <div><b>03</b><span><strong>Preserve evidence</strong><small>Export bundles and verify integrity fingerprints</small></span></div>
        <button className="quickstart-link" onClick={() => go('rules')}><BookOpen size={15}/> Detection coverage <ArrowRight size={14}/></button>
      </div>
    </section>}

    <div className="analytics-grid">
      <section className="panel activity-panel">
        <div className="panel-head"><div><span className="overline">TELEMETRY OVER TIME</span><h2>Event activity</h2><p>Observed events and finding matches in the selected window.</p></div>
          <select className="range-select" value={range} onChange={event => setRange(event.target.value)}>
            <option value="1h">Last hour</option><option value="24h">24 hours</option><option value="7d">7 days</option><option value="all">All time</option>
          </select>
        </div>
        <div className="chart-legend"><span><i className="legend-mint"/>Events</span><span><i className="legend-blue"/>Finding matches</span><b>{Number(events || 0).toLocaleString()} observed</b></div>
        <div className="chart-area">{activity.some(item => item.events) ?
          <ResponsiveContainer width="100%" height="100%"><AreaChart data={activity} margin={{top:12,right:12,left:-20,bottom:0}}>
            <defs><linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#a6f27a" stopOpacity={.24}/><stop offset="100%" stopColor="#a6f27a" stopOpacity={0}/></linearGradient></defs>
            <CartesianGrid stroke="#26374a" strokeDasharray="3 6" vertical={false}/>
            <XAxis dataKey="label" tick={{fill:'#8b99a9',fontSize:11}} axisLine={false} tickLine={false} minTickGap={24}/>
            <YAxis tick={{fill:'#8b99a9',fontSize:11}} axisLine={false} tickLine={false} allowDecimals={false}/>
            <Tooltip content={<ChartTip/>}/>
            <Area type="monotone" dataKey="events" name="Events" stroke="#a6f27a" strokeWidth={2.5} fill="url(#eventFill)" activeDot={{r:5,strokeWidth:0}}/>
            <Area type="monotone" dataKey="findings" name="Findings" stroke="#71c8f5" strokeWidth={2} fill="transparent" activeDot={{r:4}}/>
          </AreaChart></ResponsiveContainer> : <Empty icon={ChartNoAxesCombined} title="Waiting for telemetry" desc="Run a simulation or import events to populate the activity chart."/>}
        </div>
        <div className="panel-note"><span><i className="pulse-dot"/>Data from stored event timestamps</span><span>No synthetic projections</span></div>
      </section>

      <section className="panel severity-panel">
        <div className="panel-head"><div><span className="overline">RISK DISTRIBUTION</span><h2>Findings by severity</h2><p>Current evidence set</p></div><button className="link-button" onClick={() => go('detections')}>View all <ArrowUpRight size={15}/></button></div>
        <div className="donut-wrap">{severityData.length ? <>
          <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={severityData} dataKey="value" nameKey="name" innerRadius="68%" outerRadius="90%" paddingAngle={3} stroke="none">
            {severityData.map(item => <Cell key={item.name} fill={PALETTE[item.name] || '#7aaeff'}/>)}
          </Pie><Tooltip content={<ChartTip/>}/></PieChart></ResponsiveContainer>
          <div className="donut-label"><b>{Number(dashboard.findings_total || 0).toLocaleString()}</b><small>FINDINGS</small></div>
        </> : <div className="donut-empty"><ShieldCheck size={28}/><b>All quiet</b><small>No findings recorded</small></div>}</div>
        <div className="severity-legend">{['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(key =>
          <div key={key}><span><i style={{background:PALETTE[key]}}/>{key}</span><b>{Number(dashboard.severity?.[key] || 0).toLocaleString()}</b></div>
        )}</div>
      </section>
    </div>

    <div className="lower-grid">
      <section className="panel incidents-panel"><div className="panel-head"><div><span className="overline">PRIORITY QUEUE</span><h2>Recent incidents</h2><p>Correlated cases requiring analyst review.</p></div><button className="link-button" onClick={() => go('incidents')}>All incidents <ArrowUpRight size={15}/></button></div>
        <IncidentTable rows={incidents.slice(0,5)} onOpen={onIncident}/>
      </section>
      <div className="right-stack">
        <section className="panel compact-panel"><div className="panel-head"><div><span className="overline">DETECTION COVERAGE</span><h2>Top triggered rules</h2></div><button className="icon-button subtle" onClick={() => go('rules')} aria-label="Open detection library"><ArrowUpRight size={16}/></button></div>
          {topRules.length ? <div className="rule-chart"><ResponsiveContainer width="100%" height={190}><BarChart data={topRules} layout="vertical" margin={{top:2,right:18,left:2,bottom:2}}>
            <CartesianGrid stroke="#e8edf3" strokeDasharray="3 6" horizontal={false}/><XAxis type="number" hide allowDecimals={false}/>
            <YAxis type="category" dataKey="rule" width={94} tick={{fill:'#7d8da0',fontSize:10,fontFamily:'DM Mono'}} axisLine={false} tickLine={false}/>
            <Tooltip content={<ChartTip/>}/><Bar dataKey="count" name="Findings" fill="#3478d4" radius={[0,5,5,0]} barSize={13}/>
          </BarChart></ResponsiveContainer></div> : <Empty icon={Layers3} title="No rule matches" desc="Detection activity appears after telemetry ingestion."/>}
        </section>
        <section className="panel source-panel"><div className="panel-head"><div><span className="overline">INGESTION SOURCES</span><h2>Data provenance</h2></div><button className="icon-button subtle" onClick={() => go('data-sources')} aria-label="Open data sources"><ArrowUpRight size={16}/></button></div>
          {Object.keys(sources).length ? Object.entries(sources).map(([key,value]) => <div className="source-row" key={key}><span className="source-glyph"><Database size={15}/></span><span>{key || 'Unknown source'}</span><b>{value}</b></div>) : <div className="source-empty">No source data available yet.</div>}
        </section>
      </div>
    </div>
  </div>;
}
function SetupGuide({ providers, events, findings, go, onRunSimulation, onImport, busy }) {
  const [dismissed, setDismissed] = useState(() => {
    try { return window.localStorage.getItem('cloudshield.setup-guide.dismissed') === '1'; }
    catch { return false; }
  });
  const [expanded, setExpanded] = useState(true);
  const connected = providers.some(item => item.status === 'connected');
  const configured = providers.some(item => item.configured || item.enabled);
  const steps = [
    { title: 'Connect a cloud data source', detail: 'Configure a workspace-scoped AWS or Azure read-only identity.', done: connected, action: () => go('data-sources'), actionLabel: 'Configure source' },
    { title: 'Collect or import audit events', detail: 'Use an offline scenario or import supported provider audit records.', done: Number(events) > 0, action: onImport, actionLabel: 'Import events' },
    { title: 'Review detection coverage', detail: 'Inspect rule logic, severity and known coverage limitations.', done: Number(findings) > 0, action: () => go('rules'), actionLabel: 'Review rules' },
    { title: 'Investigate and preserve evidence', detail: 'Review incidents and verify exported evidence bundles.', done: Number(findings) > 0, action: () => go('evidence'), actionLabel: 'Open evidence' }
  ];
  const completed = steps.filter(step => step.done).length;
  if (dismissed) return <button className="setup-guide-reopen" onClick={() => { setDismissed(false); setExpanded(true); }}>Show workspace setup guide <ArrowRight size={14}/></button>;
  return <section className="setup-guide" aria-label="Workspace onboarding">
    <div className="setup-guide-head">
      <div><span className="overline">GETTING STARTED</span><h2>Set up your security workspace</h2><p>Complete these steps to move from an empty lab to an evidence-backed investigation workflow.</p></div>
      <div className="setup-guide-progress"><b>{completed}/4</b><small>STEPS COMPLETE</small><div><i style={{width:(completed/4*100)+'%'}}/></div></div>
    </div>
    <div className="setup-guide-track"><div className="setup-guide-track-fill" style={{width:(completed/4*100)+'%'}}/></div>
    {expanded && <div className="setup-guide-steps">{steps.map((step,index) => <article className={'setup-step '+(step.done?'is-done':'')} key={step.title}>
      <span className="setup-step-number">{step.done?<CheckCircle2 size={17}/>:String(index+1).padStart(2,'0')}</span>
      <div className="setup-step-copy"><b>{step.title}</b><small>{step.detail}</small></div>
      {step.done ? <span className="setup-step-status">Complete</span> : <button onClick={step.action}>{step.actionLabel}<ArrowUpRight size={13}/></button>}
    </article>)}</div>}
    <div className="setup-guide-foot"><button className="setup-guide-toggle" onClick={() => setExpanded(value => !value)}>{expanded?'Collapse guide':'Expand guide'}</button><div><button className="setup-guide-sim" onClick={onRunSimulation} disabled={busy}><Play size={13}/>Try offline simulation</button><button className="setup-guide-dismiss" onClick={() => { try { window.localStorage.setItem('cloudshield.setup-guide.dismissed','1'); } catch {} setDismissed(true); }}>Dismiss</button></div></div>
  </section>;
}