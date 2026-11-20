import React,{useEffect,useState} from 'react';
import {Activity,AlertTriangle,CheckCircle2,Database,LockKeyhole,Shield,ShieldCheck} from 'lucide-react';

const Panel=({title,children,aside})=><section className="panel cloud-panel"><div className="panel-head"><div><span className="overline">CLOUDSHIELD OPERATIONS</span><h2>{title}</h2></div>{aside}</div>{children}</section>;

export function CloudConnections({providers=[],request,notify,refresh,role,inventory=[],readiness}) {
 const aws=providers.find(p=>p.id==='aws')||{},azure=providers.find(p=>p.id==='azure')||{};
 const [roleArn,setRoleArn]=useState(''),[region,setRegion]=useState('us-east-1');
 const [tenantId,setTenantId]=useState(''),[subscriptionId,setSubscriptionId]=useState(''),[clientId,setClientId]=useState('');
 const [busy,setBusy]=useState(''),[externalId,setExternalId]=useState('');
 const admin=role==='admin';
 useEffect(()=>{if(aws.role_arn)setRoleArn(aws.role_arn);if(aws.region)setRegion(aws.region);if(azure.tenant_id)setTenantId(azure.tenant_id);if(azure.subscription_id)setSubscriptionId(azure.subscription_id);if(azure.managed_identity_client_id)setClientId(azure.managed_identity_client_id)},[aws.role_arn,aws.region,azure.tenant_id,azure.subscription_id,azure.managed_identity_client_id]);
 const run=async(key,fn)=>{setBusy(key);try{await fn()}catch(e){notify(e.message)}finally{setBusy('')}};
 const configureAws=()=>run('aws-save',async()=>{const r=await request('/providers/aws',{method:'POST',body:JSON.stringify({role_arn:roleArn,region})});setExternalId(r.external_id);notify('AWS role saved. Add the displayed ExternalId to the role trust policy, then test the connection.');await refresh()});
 const configureAzure=()=>run('azure-save',async()=>{await request('/providers/azure',{method:'POST',body:JSON.stringify({tenant_id:tenantId,subscription_id:subscriptionId,managed_identity_client_id:clientId||null})});notify('Azure workspace identity saved.');await refresh()});
 const enable=(provider,value)=>run(provider+'-enable',async()=>{await request('/providers/'+provider+'/enable',{method:'POST',body:JSON.stringify({enabled:value})});notify(provider.toUpperCase()+(value?' collection enabled':' collection paused'));await refresh()});
 const test=(provider)=>run(provider+'-test',async()=>{await request('/providers/'+provider+'/test',{method:'POST',body:JSON.stringify({})});notify(provider.toUpperCase()+' identity and read access verified');await refresh()});
 const collect=(provider,path)=>run(provider+'-collect',async()=>{const r=await request(path,{method:'POST',body:JSON.stringify(provider==='aws'?{lookback_minutes:60,max_pages:5,regions:[region]}:{lookback_hours:1,max_pages:5,max_records:1000})});notify('Collection complete · '+(r.events_returned??r.resource_count??0)+' records returned');await refresh()});
 return <div className="cloud-ops-stack">
  <div className="insight-banner"><LockKeyhole size={19}/><div><b>Workspace-scoped, read-only provider access</b><p>CloudShield never stores cloud access keys or client secrets. AWS uses STS AssumeRole with a unique ExternalId. Azure uses an explicitly selected managed/workload identity. Collection is disabled until an administrator enables and tests it.</p></div></div>
  <div className="provider-meta worker-meta"><span>Scheduled collector worker: <b>{readiness?.worker||'unknown'}</b></span><span>Heartbeat: {readiness?.worker_heartbeat_at?new Date(readiness.worker_heartbeat_at).toLocaleString():'not yet reported'}</span></div>
  {!admin&&<div className="auth-error">Only workspace administrators can configure or enable cloud connections. You can still view their status.</div>}
  <div className="provider-config-grid">
   <Panel title="Amazon Web Services" aside={<span className={'source-status '+(aws.status==='connected'?'status-ok':'')}><i/>{aws.status||'not configured'}</span>}>
    <p className="cloud-description">Connect one AWS account using an IAM role. The AWS deployment identity needs sts:AssumeRole permission for this role.</p>
    <label className="cloud-field">IAM role ARN<input value={roleArn} onChange={e=>setRoleArn(e.target.value)} placeholder="arn:aws:iam::123456789012:role/CloudShieldReadOnly" disabled={!admin}/></label>
    <label className="cloud-field">Default region<input value={region} onChange={e=>setRegion(e.target.value)} placeholder="us-east-1" disabled={!admin}/></label>
    {externalId&&<div className="external-id"><b>Workspace ExternalId · add to the IAM role trust policy</b><code>{externalId}</code><button className="button button-soft" onClick={()=>navigator.clipboard.writeText(externalId)}>Copy ExternalId</button></div>}
    {admin&&<div className="cloud-actions"><button className="button button-primary" disabled={!!busy||!roleArn.trim()} onClick={configureAws}>{busy==='aws-save'?'Saving…':'Save role'}</button>{aws.configured&&<><button className="button button-soft" disabled={!!busy} onClick={()=>test('aws')}>{busy==='aws-test'?'Testing…':'Test identity'}</button><button className="button button-soft" disabled={!!busy||(!aws.enabled&&aws.status!=='connected')} onClick={()=>enable('aws',!aws.enabled)}>{aws.enabled?'Pause':'Enable'} collection</button></>}</div>}
    <div className="provider-meta"><span>Last check: {aws.last_checked_at?new Date(aws.last_checked_at).toLocaleString():'—'}</span><span>Last collection: {aws.last_collected_at?new Date(aws.last_collected_at).toLocaleString():'—'}</span></div>
    {aws.enabled&&<div className="cloud-actions"><button className="button button-soft" disabled={!!busy} onClick={()=>collect('aws','/collector/aws')}>Collect CloudTrail now</button><button className="button button-soft" disabled={!!busy} onClick={()=>collect('aws','/collector/aws/inventory')}>Refresh inventory</button></div>}
   </Panel>
   <Panel title="Microsoft Azure" aside={<span className={'source-status '+(azure.status==='connected'?'status-ok':'')}><i/>{azure.status||'not configured'}</span>}>
    <p className="cloud-description">Connect a single subscription. Supply the Azure tenant and subscription IDs plus the deployment's user-assigned managed identity client ID or workload identity client ID. No client secret is accepted.</p>
    <label className="cloud-field">Tenant ID<input value={tenantId} onChange={e=>setTenantId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" disabled={!admin}/></label>
    <label className="cloud-field">Subscription ID<input value={subscriptionId} onChange={e=>setSubscriptionId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" disabled={!admin}/></label>
    <label className="cloud-field">Managed / workload identity client ID<input value={clientId} onChange={e=>setClientId(e.target.value)} placeholder="User-assigned identity client ID" disabled={!admin}/></label>
    {admin&&<div className="cloud-actions"><button className="button button-primary" disabled={!!busy||!tenantId.trim()||!subscriptionId.trim()||!clientId.trim()} onClick={configureAzure}>{busy==='azure-save'?'Saving…':'Save identity'}</button>{azure.configured&&<><button className="button button-soft" disabled={!!busy} onClick={()=>test('azure')}>{busy==='azure-test'?'Testing…':'Test identity'}</button><button className="button button-soft" disabled={!!busy||(!azure.enabled&&azure.status!=='connected')} onClick={()=>enable('azure',!azure.enabled)}>{azure.enabled?'Pause':'Enable'} collection</button></>}</div>}
    <div className="provider-meta"><span>Last check: {azure.last_checked_at?new Date(azure.last_checked_at).toLocaleString():'—'}</span><span>Last collection: {azure.last_collected_at?new Date(azure.last_collected_at).toLocaleString():'—'}</span></div>
    {azure.enabled&&<div className="cloud-actions"><button className="button button-soft" disabled={!!busy} onClick={()=>collect('azure','/collector/azure/activity-logs')}>Collect Activity Logs</button><button className="button button-soft" disabled={!!busy} onClick={()=>collect('azure','/collector/azure/inventory')}>Refresh inventory</button></div>}
   </Panel>
  </div>
  <Panel title="Live cloud inventory" aside={<span className="muted-tag">{inventory.length} records</span>}>
   <p className="cloud-description">Resource metadata discovered by the bounded read-only collectors. This is not authoritative organization-wide inventory.</p>
   <div className="table-scroll"><table><thead><tr><th>PROVIDER</th><th>RESOURCE</th><th>TYPE</th><th>LOCATION</th><th>OBSERVED</th></tr></thead><tbody>{inventory.slice(0,100).map((r,i)=><tr key={r.provider+':'+r.resource_id+i}><td>{r.provider?.toUpperCase()}</td><td><b className="mono">{r.resource_id}</b></td><td>{r.resource_type||r.type||'—'}</td><td>{r.region||r.location||'—'}</td><td>{r.observed_at?new Date(r.observed_at).toLocaleString():'—'}</td></tr>)}</tbody></table>{!inventory.length&&<div className="cloud-empty"><Database size={20}/>No live inventory collected yet.</div>}</div>
  </Panel>
 </div>;
}

export function ResponseCenter({alerts=[],responses=[],findings=[],request,notify,refresh,role,userId}) {
 const [findingId,setFindingId]=useState(''),[choices,setChoices]=useState([]),[action,setAction]=useState(''),[rationale,setRationale]=useState(''),[busy,setBusy]=useState('');
 const responder=['admin','responder'].includes(role);
 useEffect(()=>{if(!findingId){setChoices([]);setAction('');return}let active=true;request('/findings/'+encodeURIComponent(findingId)+'/recommendations').then(r=>{if(active){setChoices(r.recommendations||[]);setAction(r.recommendations?.[0]?.action||'')}}).catch(e=>notify(e.message));return()=>{active=false}},[findingId]);
 const submit=async()=>{setBusy('request');try{await request('/responses',{method:'POST',body:JSON.stringify({finding_id:findingId,action,rationale})});setRationale('');notify('Response request submitted for independent approval');await refresh()}catch(e){notify(e.message)}finally{setBusy('')}};
 const acknowledge=async id=>{setBusy(id);try{await request('/alerts/'+encodeURIComponent(id)+'/acknowledge',{method:'POST',body:JSON.stringify({})});await refresh()}catch(e){notify(e.message)}finally{setBusy('')}};
 const decide=async(id,approve)=>{setBusy(id);try{await request('/responses/'+encodeURIComponent(id)+'/decision',{method:'POST',body:JSON.stringify({approve,note:approve?'Approved after independent review':'Rejected after review'})});notify(approve?'Request approved. No cloud action was executed.':'Request rejected.');await refresh()}catch(e){notify(e.message)}finally{setBusy('')}};
 return <div className="cloud-ops-stack">
  <div className="insight-banner"><ShieldCheck size={19}/><div><b>Human approval and evidence first</b><p>Recommendations are guidance only. A second workspace member must approve a request. Approval records intent; it does not execute a cloud write. Automated remediation remains deliberately disabled pending provider-specific security review.</p></div></div>
  <Panel title="High-severity alerts" aside={<span className="muted-tag">{alerts.filter(a=>!a.acknowledged_at).length} unacknowledged</span>}>
   <div className="alert-list">{alerts.map(a=><article className="alert-row" key={a.alert_id}><div className="alert-icon"><AlertTriangle size={18}/></div><div className="alert-copy"><div><b>{a.title}</b><span className={'severity sev-'+a.severity.toLowerCase()}>{a.severity}</span></div><p>{a.summary}</p><small>{new Date(a.created_at).toLocaleString()} · Finding {a.finding_id.slice(0,12)}</small></div>{!a.acknowledged_at?<button className="button button-soft" disabled={!responder||!!busy} onClick={()=>acknowledge(a.alert_id)}>Acknowledge</button>:<span className="ack-state"><CheckCircle2 size={14}/>Acknowledged</span>}</article>)}{!alerts.length&&<div className="cloud-empty"><CheckCircle2 size={20}/>No high-severity alerts have been generated.</div>}</div>
  </Panel>
  <Panel title="Guided response request">
   {!responder&&<div className="auth-error">Responder or administrator role required to submit a response request.</div>}
   <label className="cloud-field">Finding<select value={findingId} onChange={e=>setFindingId(e.target.value)}><option value="">Choose a finding…</option>{findings.filter(f=>['HIGH','CRITICAL'].includes(String(f.severity).toUpperCase())).map(f=><option key={f.finding_id} value={f.finding_id}>{f.severity} · {f.title||f.rule_id}</option>)}</select></label>
   <label className="cloud-field">Recommended action<select value={action} onChange={e=>setAction(e.target.value)}>{choices.map(c=><option key={c.action} value={c.action}>{c.title}</option>)}</select></label>
   {choices.find(c=>c.action===action)&&<p className="cloud-description">{choices.find(c=>c.action===action).rationale}</p>}
   <label className="cloud-field">Investigation context<textarea value={rationale} onChange={e=>setRationale(e.target.value)} maxLength={2000} rows={3} placeholder="Explain why this response is appropriate and what evidence supports it."/></label>
   <button className="button button-primary" disabled={!responder||!findingId||!action||rationale.trim().length<10||!!busy} onClick={submit}>{busy==='request'?'Submitting…':'Submit for independent approval'}</button>
  </Panel>
  <Panel title="Approval queue" aside={<span className="muted-tag">{responses.filter(r=>r.status==='pending').length} pending</span>}>
   <div className="alert-list">{responses.map(r=><article className="alert-row" key={r.request_id}><div className="alert-icon"><Shield size={18}/></div><div className="alert-copy"><div><b>{r.action.replaceAll('_',' ')}</b><span className="muted-tag">{r.status}</span></div><p>{r.rationale}</p><small>Requested by {r.requested_by} · {new Date(r.requested_at).toLocaleString()}</small>{r.decided_by&&<small>Decision by {r.decided_by}: {r.decision_note}</small>}</div>{r.status==='pending'&&role==='admin'&&r.requested_by!==userId&&<div className="cloud-actions"><button className="button button-primary" disabled={!!busy} onClick={()=>decide(r.request_id,true)}>Approve</button><button className="button button-soft" disabled={!!busy} onClick={()=>decide(r.request_id,false)}>Reject</button></div>}</article>)}{!responses.length&&<div className="cloud-empty"><Activity size={20}/>No response requests yet.</div>}</div>
  </Panel>
 </div>;
}
