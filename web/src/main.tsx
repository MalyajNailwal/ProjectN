import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, ArrowDownRight, ArrowRight, Check, ChevronRight, Circle, CircleAlert, CircleCheck, CircleMinus, CircleStop, CircleX, Clock3, Code2, Download, Globe2, Layers3, LoaderCircle, LockKeyhole, Radar, ScanSearch, Server, Shield, ShieldAlert, TerminalSquare, Zap } from 'lucide-react'
import './style.css'
import './comparison.css'

type Scanner = {id:string;label:string;ready:boolean;source_present:boolean;limitations:string[];resolution:string|null}
type Finding = {id:string;scanner:string;title:string;severity:string;location:string;evidence:string;remediation:string;rule:string;confidence:string;verification:string}
type Limitation = {code:string;message:string;resolution:string;scanner:string|null}
type Step = {id:string;label:string;state:string;summary?:string;started_at?:number;finished_at?:number}
type Stage = {id:string;label:string;state:string;summary:string;details?:Record<string,unknown>}
type Report = {target:{url:string|null;repo_url:string|null;local_path:string|null;commit:string|null};started_at:number;finished_at:number;cancelled?:boolean;steps?:Step[];findings:Finding[];stages:Stage[];limitations:Limitation[];summary:{findings:number;completed:number;incomplete:number}}
type Scan = {id:string;created:number;status:string;progress:string;target:{url?:string;repo_url?:string;local_path?:string};result:Report|null;error:string|null;steps?:Step[]}
type ScanListItem = Pick<Scan,'id'|'created'|'status'|'progress'> & {target:string}
type Comparison = {summary:{still_present:number;not_observed_on_rescan:number;not_verifiable:number;new:number}}
type RemediationDraft = {summary:string;fix_steps:string[];verification:string;uncertainty:string;citation:string;model:string;status:string}
type AssistantStatus = {provider:string;external:boolean;configured:boolean;mode:string}
type FullConfig = {port_range:string;crawl_depth:number;crawl_duration_minutes:number;template_rate:number;inventory_limit:number;browser_page_limit:number}
type View = 'overview'|'findings'|'coverage'|'assets'|'setup'

const nav: {id:View;label:string;icon:React.ElementType}[] = [
  {id:'overview',label:'Overview',icon:Layers3},
  {id:'findings',label:'Findings',icon:ShieldAlert},
  {id:'coverage',label:'Coverage',icon:Radar},
  {id:'assets',label:'Assets',icon:Globe2},
  {id:'setup',label:'Tool setup',icon:TerminalSquare},
]
const formatTime = (seconds:number) => new Date(seconds*1000).toLocaleString()
const shortId = (id:string) => id.slice(0,8).toUpperCase()
const elapsed = (seconds:number) => {const s=Math.max(0,Math.round(seconds));return s<60?`${s}s`:s<3600?`${Math.floor(s/60)}m ${s%60}s`:`${Math.floor(s/3600)}h ${Math.floor(s%3600/60)}m`}
const finishedStep = new Set(['completed','partial','failed','skipped'])
const stepIcon:Record<string,React.ElementType> = {pending:Circle,running:LoaderCircle,completed:Check,partial:CircleAlert,failed:CircleX,skipped:CircleMinus,cancelled:CircleStop,not_run:CircleMinus}
const stepWords:Record<string,string> = {pending:'Waiting',running:'Running now',skipped:'Skipped',cancelled:'Stopped by user',not_run:'Not run because the scan was stopped'}
const severityOrder:Record<string,number> = {critical:0,high:1,medium:2,low:3,info:4,unknown:5}

async function jsonFetch<T>(url:string, init?:RequestInit):Promise<T> {
  const response = await fetch(url, init)
  if (!response.ok) {
    const body = await response.json().catch(()=>({detail:'Request failed'}))
    const detail = body.detail
    const message = typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((issue:{msg?:string;loc?:string[]})=>`${issue.loc?.at(-1)||'Input'}: ${issue.msg||'invalid value'}`).join('; ') : 'Request failed'
    throw new Error(message)
  }
  return response.json()
}

function App(){
  const [view,setView] = useState<View>('overview')
  const [scanners,setScanners] = useState<Scanner[]>([])
  const [history,setHistory] = useState<ScanListItem[]>([])
  const [scan,setScan] = useState<Scan|null>(null)
  const [url,setUrl] = useState('')
  const [repo,setRepo] = useState('')
  const [folder,setFolder] = useState('')
  const [journeyFile,setJourneyFile] = useState('')
  const [apiSpecFile,setApiSpecFile] = useState('')
  const [oobServer,setOobServer] = useState('')
  const [oobTokenEnv,setOobTokenEnv] = useState('')
  const [profile,setProfile] = useState<'standard'|'deep'|'full'>('standard')
  const [authorized,setAuthorized] = useState(false)
  const [portRange,setPortRange] = useState('')
  const [crawlDepth,setCrawlDepth] = useState('')
  const [crawlMinutes,setCrawlMinutes] = useState('')
  const [templateRate,setTemplateRate] = useState('')
  const [inventoryLimit,setInventoryLimit] = useState('')
  const [browserPageLimit,setBrowserPageLimit] = useState('')
  const [fullDefaults,setFullDefaults] = useState<FullConfig|null>(null)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const [submitError,setSubmitError] = useState('')
  const [submittedScanId,setSubmittedScanId] = useState<string|null>(null)
  const [selected,setSelected] = useState<Finding|null>(null)
  const [severity,setSeverity] = useState('all')
  const [comparison,setComparison] = useState<Comparison|null>(null)
  const [draft,setDraft] = useState<RemediationDraft|null>(null)
  const [draftError,setDraftError] = useState('')
  const [draftBusy,setDraftBusy] = useState(false)
  const [assistantStatus,setAssistantStatus] = useState<AssistantStatus|null>(null)
  const [allowExternal,setAllowExternal] = useState(false)
  const [stopping,setStopping] = useState(false)
  const [now,setNow] = useState(()=>Date.now()/1000)
  const active = !!scan && ['queued','running'].includes(scan.status)

  useEffect(()=>{
    jsonFetch<Scanner[]>('/api/scanners').then(setScanners).catch(e=>setError(e.message))
    jsonFetch<AssistantStatus>('/api/assistant/status').then(setAssistantStatus).catch(()=>{})
    jsonFetch<FullConfig>('/api/config/full').then(setFullDefaults).catch(e=>setError(e.message))
    jsonFetch<ScanListItem[]>('/api/scans').then(items=>{
      setHistory(items)
      if(items.length) jsonFetch<Scan>(`/api/scans/${items[0].id}`).then(setScan).catch(()=>{})
    }).catch(e=>setError(e.message))
  },[])
  useEffect(()=>{
    if(!scan || !['queued','running'].includes(scan.status)) return
    const timer = window.setInterval(()=>jsonFetch<Scan>(`/api/scans/${scan.id}`).then(next=>{
      setScan(next)
      if(!['queued','running'].includes(next.status)){
        jsonFetch<ScanListItem[]>('/api/scans').then(setHistory).catch(()=>{})
        jsonFetch<Scanner[]>('/api/scanners').then(setScanners).catch(()=>{})
      }
    }).catch(()=>{}),1300)
    return ()=>window.clearInterval(timer)
  },[scan?.id,scan?.status])
  useEffect(()=>{
    setStopping(false)
    if(!active) return
    const timer = window.setInterval(()=>setNow(Date.now()/1000),1000)
    return ()=>window.clearInterval(timer)
  },[active,scan?.id])
  useEffect(()=>{
    setComparison(null)
    if(!scan?.result) return
    const current=scan.target
    const previous=history.find(item=>{
      if(item.id===scan.id || item.created>=scan.created || item.status!=='completed') return false
      try{
        const target=JSON.parse(item.target)
        return ['url','repo_url','local_path'].every(key=>(target[key]||null)===(current[key as keyof typeof current]||null))
      }catch{return false}
    })
    if(previous) jsonFetch<Comparison>(`/api/scans/${scan.id}/compare/${previous.id}`).then(setComparison).catch(()=>{})
  },[scan?.id,scan?.status,history])

  const report=scan?.result
  const ready=scanners.filter(s=>s.ready).length
  const steps=scan?.steps?.length?scan.steps:report?.steps||[]
  const doneSteps=steps.filter(step=>finishedStep.has(step.state)).length
  const percent=scan?.status==='completed'?100:steps.length?Math.round(doneSteps/steps.length*100):0
  const currentStep=steps.find(step=>step.state==='running')
  const filtered=useMemo(()=>[...(report?.findings||[])].filter(f=>severity==='all'||f.severity===severity).sort((a,b)=>(severityOrder[a.severity]??6)-(severityOrder[b.severity]??6)),[report,severity])
  const ports=report?.stages.find(s=>s.id==='ports')?.details?.ports as {host:string;port:number;protocol:string;state:string;service:string;version:string}[]|undefined
  const urls=report?.stages.find(s=>s.id==='crawler')?.details?.urls as string[]|undefined
  const apiEndpoints=report?.stages.find(s=>s.id==='crawler')?.details?.api_endpoints as {method:string;url:string;status:number|null;content_type:string}[]|undefined
  const renderedPages=report?.stages.find(s=>s.id==='browser')?.details?.pages as {url:string;title:string;status:number|null}[]|undefined
  const renderedForms=report?.stages.find(s=>s.id==='browser')?.details?.forms as {page:string;action:string;method:string;fields:{name:string;type:string}[]}[]|undefined
  const browserApis=report?.stages.find(s=>s.id==='browser')?.details?.api_endpoints as {method:string;url:string;status:number|null}[]|undefined
  const apiContract=report?.stages.find(s=>s.id==='api_spec')?.details as {declared?:{method:string;path:string;observed:boolean}[];undocumented_observed?:{method:string;url:string}[]}|undefined
  const journeyResults=report?.stages.find(s=>s.id==='journeys')?.details?.journeys as {name:string;covers:string[];passed:boolean;completed_steps:number;issues:{step:number;type:string}[]}[]|undefined
  const performanceScores=report?.stages.find(s=>s.id==='performance')?.details?.categories as Record<string,{title:string;score:number|null}>|undefined
  const tlsDetails=report?.stages.find(s=>s.id==='tls')?.details as {protocol?:string;cipher?:string;days_until_expiry?:number}|undefined
  const technologies=report?.stages.find(s=>s.id==='technology')?.details?.technologies as string[]|undefined

  async function submit(event:React.FormEvent){
    event.preventDefault();setError('');setSubmitError('');setBusy(true)
    try{
      const fullOptions=profile==='full'?{port_range:portRange.trim()||null,crawl_depth:crawlDepth?Number(crawlDepth):null,crawl_duration_minutes:crawlMinutes?Number(crawlMinutes):null,template_rate:templateRate?Number(templateRate):null,inventory_limit:inventoryLimit?Number(inventoryLimit):null,browser_page_limit:browserPageLimit?Number(browserPageLimit):null}:{}
      const enteredUrl=url.trim()
      const normalizedUrl=enteredUrl&&!enteredUrl.includes('://')?`https://${enteredUrl}`:enteredUrl
      const result=await jsonFetch<{id:string}>('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:normalizedUrl||null,repo_url:repo.trim()||null,local_path:folder.trim()||null,journey_file:profile==='full'?journeyFile.trim()||null:null,api_spec_file:apiSpecFile.trim()||null,oob_server:profile==='full'?oobServer.trim()||null:null,oob_token_env:profile==='full'?oobTokenEnv.trim()||null:null,profile,authorized_intrusive:authorized,...fullOptions})})
      setScan({id:result.id,created:Date.now()/1000,status:'queued',progress:'Waiting to start',target:{url:normalizedUrl,repo_url:repo,local_path:folder},result:null,error:null})
      setSubmittedScanId(result.id)
      setView('overview')
      const items=await jsonFetch<ScanListItem[]>('/api/scans');setHistory(items)
    }catch(e){setSubmitError((e as Error).message)}finally{setBusy(false)}
  }
  async function stopScan(){
    if(!scan) return
    setStopping(true)
    try{await jsonFetch(`/api/scans/${scan.id}/cancel`,{method:'POST'})}catch(e){setError((e as Error).message);setStopping(false)}
  }
  async function openScan(id:string){
    setError('');setSelected(null)
    try{setScan(await jsonFetch<Scan>(`/api/scans/${id}`));setView('overview')}catch(e){setError((e as Error).message)}
  }
  async function requestDraft(item:Finding){
    if(!scan) return
    setDraft(null);setDraftError('');setDraftBusy(true)
    try{setDraft(await jsonFetch<RemediationDraft>(`/api/scans/${scan.id}/findings/${item.id}/draft`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({allow_external:allowExternal})}))}
    catch(e){setDraftError((e as Error).message)}finally{setDraftBusy(false)}
  }
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Radar size={25} strokeWidth={2.5}/></div><div><strong>PROJECT<span>N</span></strong><small>SECURITY WORKSTATION</small></div></div>
      <div className="workspace-label">WORKSPACE <span>01</span></div>
      <nav className="main-nav">{nav.map(item=><button className={'nav-item '+(view===item.id?'active':'')} key={item.id} onClick={()=>setView(item.id)}><item.icon size={18}/><span>{item.label}</span>{item.id==='setup'&&scanners.length>0&&<b>{ready}/{scanners.length}</b>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="local-indicator"><span className="pulse"/><span>LOCAL ENGINE</span><b>ONLINE</b></div><p>Scans run on this machine.<br/>Reports stay in local storage.</p></div>
    </aside>
    <div className="main-area">
      <header className="topbar"><div className="breadcrumb">WORKSPACE <ChevronRight size={13}/> {view.toUpperCase()}</div><div className="top-actions"><span className="desktop-only">WINDOWS + MACOS</span><div className="avatar">N</div></div></header>
      <main className="content">
        {error&&<div className="error-banner"><CircleAlert size={17}/>{error}<button onClick={()=>setError('')}>Dismiss</button></div>}
        {view==='overview'&&<>
          <section className="hero"><div className="hero-copy"><div className="eyebrow"><span className="eyebrow-line"/> LOCAL SECURITY OPERATIONS</div><h1>See the whole<br/><em>attack surface.</em></h1><p>Scan a website, inspect a public codebase, and turn raw signals into a focused plan to fix what matters.</p><div className="hero-badges"><span><Check size={14}/> Evidence first</span><span><Check size={14}/> No cloud account</span><span><Check size={14}/> Fix verification</span></div></div><div className="hero-art"><div className="radar-ring r1"/><div className="radar-ring r2"/><div className="radar-ring r3"/><div className="radar-line"/><div className="radar-center"><ScanSearch size={36}/></div><span className="radar-coordinate">SCOPE / TARGET_01</span><span className="radar-dot dot-one"/><span className="radar-dot dot-two"/></div></section>
          <section className="dashboard-grid"><div className="scan-card"><div className="section-heading"><div><span className="mini-label">NEW ASSESSMENT</span><h2>Start a scan</h2></div><span className="step-count">01 / CONFIGURE</span></div><form onSubmit={submit}><label className="field-label" htmlFor="website">Website URL <span>LIVE SURFACE</span></label><div className="input-wrap"><Globe2 size={18}/><input id="website" value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://your-site.com"/></div><div className="or-divider"><span/>AND / OR<span/></div><label className="field-label" htmlFor="repo">Public GitHub repository <span>SOURCE CODE</span></label><div className="input-wrap"><Code2 size={18}/><input id="repo" value={repo} onChange={e=>setRepo(e.target.value)} placeholder="https://github.com/owner/repository"/></div><label className="field-label secondary-label" htmlFor="folder">Or local source folder <span>OPTIONAL</span></label><div className="input-wrap"><Server size={18}/><input id="folder" value={folder} onChange={e=>setFolder(e.target.value)} placeholder="/path/to/your/project"/></div><label className="field-label secondary-label" htmlFor="api-spec">Local OpenAPI file <span>OPTIONAL</span></label><div className="input-wrap"><Code2 size={18}/><input id="api-spec" value={apiSpecFile} onChange={e=>setApiSpecFile(e.target.value)} placeholder="/path/to/openapi.yaml"/></div><div className="profile-row"><button type="button" className={'profile '+(profile==='standard'?'selected':'')} onClick={()=>setProfile('standard')}><Shield size={17}/><span><strong>Standard</strong><small>Discovery & inventory</small></span></button><button type="button" className={'profile '+(profile==='deep'?'selected':'')} onClick={()=>setProfile('deep')}><Zap size={17}/><span><strong>Deep</strong><small>Template checks</small></span></button><button type="button" className={'profile '+(profile==='full'?'selected':'')} onClick={()=>setProfile('full')}><Radar size={17}/><span><strong>Full scope</strong><small>All TCP ports · JS crawl · broad templates</small></span></button></div>{profile==='full'&&<div className="full-options"><p>Full scan settings <span>Leave blank to use config/full_scan.json</span></p><div className="full-options-grid"><label>TCP ports<input value={portRange} onChange={e=>setPortRange(e.target.value)} placeholder={fullDefaults?.port_range||""}/></label><label>Crawl depth<input type="number" min="1" value={crawlDepth} onChange={e=>setCrawlDepth(e.target.value)} placeholder={String(fullDefaults?.crawl_depth??"")}/></label><label>Crawl minutes<input type="number" min="1" value={crawlMinutes} onChange={e=>setCrawlMinutes(e.target.value)} placeholder={String(fullDefaults?.crawl_duration_minutes??"")}/></label><label>Template requests/sec<input type="number" min="1" value={templateRate} onChange={e=>setTemplateRate(e.target.value)} placeholder={String(fullDefaults?.template_rate??"")}/></label><label>Report endpoints<input type="number" min="1" value={inventoryLimit} onChange={e=>setInventoryLimit(e.target.value)} placeholder={String(fullDefaults?.inventory_limit??"")}/></label><label>Rendered pages<input type="number" min="1" value={browserPageLimit} onChange={e=>setBrowserPageLimit(e.target.value)} placeholder={String(fullDefaults?.browser_page_limit??"")}/></label></div>{url.trim()&&<label className="journey-path">Journey JSON file <span>Optional · credentials come from local environment variables</span><input value={journeyFile} onChange={e=>setJourneyFile(e.target.value)} placeholder="/path/to/journeys.json"/></label>}{url.trim()&&<label className="journey-path">Self-hosted OOB callback HTTPS origin <span>Optional · must be reachable by the target</span><input value={oobServer} onChange={e=>setOobServer(e.target.value)} placeholder="https://callback.example.com"/></label>}{url.trim()&&oobServer.trim()&&<label className="journey-path">Callback token environment variable <span>Optional · token stays local</span><input value={oobTokenEnv} onChange={e=>setOobTokenEnv(e.target.value)} placeholder="PROJECTN_OOB_TOKEN"/></label>}</div>}{profile==='full'&&url.trim()&&<label className="auth-confirm"><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)}/><span>I am authorized to run intrusive checks against this website.</span></label>}<button className="primary-btn" disabled={busy||(!url.trim()&&!repo.trim()&&!folder.trim())||(profile==='full'&&!!url.trim()&&!authorized)}>{busy?'Preparing scan…':'Launch assessment'}<ArrowRight size={18}/></button>{submitError&&<div className="submit-feedback error" role="alert">{submitError}</div>}{submittedScanId===scan?.id&&<div className="submit-feedback progress" role="status">Scan #{shortId(scan.id)} {scan.status}{steps.length>0&&` · ${percent}%`} · {currentStep?.label||scan.progress}</div>}<p className="form-note">Scan only sites and systems you are authorized to assess.</p></form></div>
          <div className="right-stack"><div className="status-card"><div className="section-heading"><div><span className="mini-label">SYSTEM STATUS</span><h2>Tool readiness</h2></div><Activity size={18}/></div><div className="readiness-number"><strong>{scanners.length?ready:"—"}</strong><span> / {scanners.length||'—'}<small>TOOLS READY</small></span></div><div className="readiness-track"><div style={{width:`${scanners.length?ready/scanners.length*100:0}%`}}/></div><button className="text-link" onClick={()=>setView('setup')}>View setup details <ArrowRight size={16}/></button></div><div className="run-card"><div className="section-heading"><div><span className="mini-label">LATEST ACTIVITY</span><h2>{scan?'Current assessment':'No scans yet'}</h2></div><Clock3 size={18}/></div>{scan?<><div className="run-id">#{shortId(scan.id)} <span className={'run-state '+scan.status}>{scan.status.toUpperCase()}</span>{active&&<span className="run-clock">{elapsed(now-scan.created)}</span>}</div>{steps.length>0&&<div className="run-progress"><div className="run-progress-head"><strong>{percent}%</strong><span>{doneSteps} of {steps.length} steps finished</span></div><div className="readiness-track" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}><div style={{width:`${percent}%`}}/></div></div>}<p className="run-now" aria-live="polite">{currentStep?<><LoaderCircle size={14} className="spin"/>{currentStep.label} · {elapsed(now-(currentStep.started_at||now))}</>:scan.progress}</p><div className="run-target">{scan.target.url||scan.target.repo_url||scan.target.local_path||'Target pending'}</div>{active&&<button type="button" className="stop-btn" onClick={stopScan} disabled={stopping}><CircleStop size={15}/>{stopping?'Stopping scanners…':'Stop scan'}</button>}{scan.status==='failed'&&scan.error&&<p className="run-error">{scan.error}</p>}{scan.result&&<button className="text-link" onClick={()=>setView('findings')}>{scan.status==='cancelled'?'Explore partial report':'Explore report'} <ArrowRight size={16}/></button>}</>:<p>Run your first assessment to start building a local history of findings and coverage.</p>}</div></div></section>
          {steps.length>0&&<section className="steps-section"><div className="section-heading"><div><span className="mini-label">SCAN PLAN · #{shortId(scan!.id)}</span><h2>{active?'What is happening now':'What ran'}</h2></div><span className="history-count">{doneSteps} / {steps.length} FINISHED</span></div><ol className="step-list">{steps.map(step=>{const Icon=stepIcon[step.state]||Circle;const seconds=step.started_at?(step.finished_at||now)-step.started_at:null;return <li key={step.id} className={'step '+step.state}><span className="step-icon"><Icon size={16} className={step.state==='running'?'spin':undefined}/></span><span className="step-label"><strong>{step.label}</strong><small>{step.summary||stepWords[step.state]||step.state}</small></span><span className="step-time">{seconds===null?'':elapsed(seconds)}</span></li>})}</ol></section>}
          <section className="history-section"><div className="section-heading"><div><span className="mini-label">ASSESSMENT LOG</span><h2>Recent scans</h2></div><span className="history-count">{history.length} RECORDS</span></div>{history.length?<div className="history-table">{history.map(item=>{let target:Record<string,string|null>={};try{target=JSON.parse(item.target)}catch{}return <button key={item.id} onClick={()=>openScan(item.id)}><span className="history-icon"><Radar size={18}/></span><span className="history-target"><strong>{target.url||target.repo_url||target.local_path||'Unknown target'}</strong><small>#{shortId(item.id)} · {formatTime(item.created)}</small></span><span className={'history-status '+item.status}>{item.status}</span><ArrowRight size={17}/></button>})}</div>:<div className="empty-state"><Radar size={24}/><span>Your first scan will appear here.</span></div>}</section>
        </>}
        {view!=='overview'&&<div className="page-title"><div><div className="eyebrow"><span className="eyebrow-line"/> ASSESSMENT / {view.toUpperCase()}</div><h1>{view==='findings'?'Findings.':view==='coverage'?'Coverage.':view==='assets'?'Assets.':'Tool setup.'}</h1><p>{view==='findings'?'Evidence, impact and precise next steps.':view==='coverage'?'What ran, what did not, and how to close the gaps.':view==='assets'?'What this assessment actually observed.':'Local source and executable readiness for every scanner.'}</p></div>{report&&<a className="export-button" href={`/api/scans/${scan?.id}/export`}><Download size={17}/> Export JSON</a>}</div>}
        {view==='findings'&&<>{comparison&&<div className="comparison-note"><strong>Rescan comparison</strong><span>{comparison.summary.still_present} still present · {comparison.summary.not_observed_on_rescan} not observed · {comparison.summary.not_verifiable} not verifiable · {comparison.summary.new} new</span></div>}<div className="finding-toolbar"><div className="result-count"><strong>{report?.findings.length??0}</strong> findings {scan&&<span>· #{shortId(scan.id)}</span>}</div><select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="all">All severities</option>{['critical','high','medium','low','info','unknown'].map(level=><option key={level} value={level}>{level}</option>)}</select></div>{filtered.length?<div className="findings-list">{filtered.map(item=><button key={item.id} className="finding-row" onClick={()=>{setSelected(item);setDraft(null);setDraftError("");setAllowExternal(false)}}><span className={'severity-dot '+item.severity}/><span><strong>{item.title}</strong><small>{item.location||item.scanner}</small></span><span className={'severity-pill '+item.severity}>{item.severity}</span><ArrowRight size={18}/></button>)}</div>:<div className="empty-state large"><Shield size={32}/><h3>{report?'No findings in this view':'No report selected'}</h3><p>{report?'Check Coverage to see which checks completed and which need another run.':'Start a scan from Overview to generate findings.'}</p></div>}</>}
        {view==='coverage'&&<><div className="coverage-summary"><div><span>COMPLETED STAGES</span><strong>{report?.summary.completed??0}</strong></div><div><span>INCOMPLETE STAGES</span><strong>{report?.summary.incomplete??0}</strong></div><div><span>LIMITATIONS</span><strong>{report?.limitations.length??0}</strong></div></div><div className="coverage-columns"><section className="panel"><div className="section-heading"><div><span className="mini-label">EXECUTION</span><h2>Scanner stages</h2></div></div>{report?.stages.length?report.stages.map(stage=><div key={stage.id} className="stage-row"><span className={'stage-icon '+stage.state}>{stage.state==='completed'?<CircleCheck size={18}/>:<CircleAlert size={18}/>}</span><span><strong>{stage.label}</strong><small>{stage.summary}</small></span><span className={'stage-state '+stage.state}>{stage.state}</span></div>):<div className="empty-inline">No stages recorded yet.</div>}</section><section className="panel"><div className="section-heading"><div><span className="mini-label">NEXT ACTIONS</span><h2>Coverage gaps</h2></div></div>{report?.limitations.length?report.limitations.map((item,index)=><div className="gap-row" key={`${item.code}-${index}`}><div className="gap-number">{String(index+1).padStart(2,'0')}</div><div><strong>{item.message}</strong><p>{item.resolution}</p></div></div>):<div className="empty-inline">No limitations recorded for the selected scan.</div>}</section></div></>}
        {view==='assets'&&<><div className="asset-grid"><section className="panel"><div className="section-heading"><div><span className="mini-label">NETWORK</span><h2>Ports & services</h2></div><Server size={18}/></div>{ports?.length?ports.map((port,index)=><div className="asset-row" key={`${port.host}-${port.port}-${index}`}><span className="port-number">{port.port}<small>/{port.protocol}</small></span><span><strong>{port.service}{port.version&&` ${port.version}`}</strong><small>{port.host}</small></span><span className={'port-state '+port.state}>{port.state}</span></div>):<div className="empty-inline">No port inventory available. Check scanner setup and coverage.</div>}</section><section className="panel"><div className="section-heading"><div><span className="mini-label">WEB SURFACE</span><h2>Discovered routes</h2></div><Globe2 size={18}/></div>{urls?.length?urls.map((route,index)=><div className="url-row" key={`${route}-${index}`}><span>{route}</span><ArrowDownRight size={15}/></div>):<div className="empty-inline">No routes recorded. Check crawler status and target access.</div>}</section></div><section className="panel tech-panel"><div className="section-heading"><div><span className="mini-label">OBSERVED API SURFACE</span><h2>JSON endpoints</h2></div></div>{apiEndpoints?.length?<div>{apiEndpoints.map((item,index)=><div className="url-row" key={`${item.method}-${item.url}-${index}`}><span>{item.method} · HTTP {item.status??"?"} · {item.url}</span><ArrowDownRight size={15}/></div>)}</div>:<div className="empty-inline">No JSON endpoints were observed in this scoped crawl. This is not a complete API count.</div>}</section><section className="panel tech-panel"><div className="section-heading"><div><span className="mini-label">BROWSER OBSERVED</span><h2>Rendered pages & forms</h2></div></div>{renderedPages?.length?<div>{renderedPages.map((item,index)=><div className="url-row" key={`${item.url}-${index}`}><span>HTTP {item.status??"?"} · {item.title||item.url} · {item.url}</span></div>)}{renderedForms?.map((item,index)=><div className="url-row" key={`${item.page}-form-${index}`}><span>{item.method} form · {item.action} · {item.fields.map(field=>field.type).join(", ")}</span></div>)}</div>:<div className="empty-inline">No rendered-page inventory available. Check Full scan browser coverage.</div>}</section><section className="panel tech-panel"><div className="section-heading"><div><span className="mini-label">BROWSER API TRAFFIC</span><h2>Observed requests</h2></div></div>{browserApis?.length?<div>{browserApis.map((item,index)=><div className="url-row" key={`${item.method}-${item.url}-${index}`}><span>{item.method} · HTTP {item.status??"?"} · {item.url}</span></div>)}</div>:<div className="empty-inline">No JSON response was observed in rendered pages.</div>}</section><section className="panel tech-panel"><div className="section-heading"><div><span className="mini-label">ACCOUNT FLOWS</span><h2>Configured journeys</h2></div></div>{journeyResults?.length?<div>{journeyResults.map((item,index)=><div className="url-row" key={`${item.name}-${index}`}><span>{item.passed?"Passed":"Needs review"} · {item.name} · {item.completed_steps} steps · {item.covers.join(", ")||"coverage unspecified"}{item.issues.length?` · ${item.issues.map(issue=>issue.type).join(", ")}`:""}</span></div>)}</div>:<div className="empty-inline">No controlled account journey was configured for this scan.</div>}</section><section className="panel tech-panel"><div className="section-heading"><div><span className="mini-label">TLS & PAGE QUALITY</span><h2>Connection and Lighthouse</h2></div></div>{tlsDetails?.protocol&&<div className="url-row"><span>{tlsDetails.protocol} · {tlsDetails.cipher} · certificate {tlsDetails.days_until_expiry} days remaining</span></div>}{performanceScores&&Object.entries(performanceScores).map(([key,item])=><div className="url-row" key={key}><span>{item.title||key} · {item.score==null?"unscored":`${Math.round(item.score*100)}/100`}</span></div>)}{!tlsDetails?.protocol&&!performanceScores&&<div className="empty-inline">No verified TLS or Lighthouse measurements available.</div>}</section><section className="panel tech-panel"><div className="section-heading"><div><span className="mini-label">API CONTRACT</span><h2>Documented operations</h2></div></div>{apiContract?.declared?.length?<div>{apiContract.declared.map((item,index)=><div className="url-row" key={`${item.method}-${item.path}-${index}`}><span>{item.method} · {item.path} · {item.observed?"Observed in this scan":"Not observed"}</span></div>)}{apiContract.undocumented_observed?.map((item,index)=><div className="url-row" key={`${item.method}-${item.url}-${index}`}><span>Observed, absent from spec · {item.method} · {item.url}</span></div>)}</div>:<div className="empty-inline">No local OpenAPI contract was supplied for this scan.</div>}</section><section className="panel tech-panel"><div className="section-heading"><div><span className="mini-label">FINGERPRINT</span><h2>Technologies</h2></div></div>{technologies?.length?<div className="tech-list">{technologies.map(item=><span key={item}>{item}</span>)}</div>:<div className="empty-inline">No technology profile available.</div>}</section></>}
        {view==='setup'&&<><div className="setup-intro"><div><span className="mini-label">SOURCE-DRIVEN TOOLCHAIN</span><h2>Local tools, transparent status.</h2><p>Each scanner needs its upstream source and a local executable. Missing tools are reported as coverage gaps; they never produce an empty “passed” result.</p></div><div className="setup-tally"><strong>{scanners.length?ready:"—"}<span>/{scanners.length||'—'}</span></strong><small>READY</small></div></div><div className="setup-list">{scanners.map(tool=><div className="setup-row" key={tool.id}><div className={'setup-icon '+(tool.ready?'ready':'missing')}>{tool.ready?<Check size={20}/>:<CircleAlert size={20}/>}</div><div><strong>{tool.label}</strong><small>{tool.ready?'Source and runtime available':tool.limitations.join(' · ')}</small>{!tool.ready&&<p>{tool.resolution}</p>}</div><span className={'setup-badge '+(tool.ready?'ready':'missing')}>{tool.ready?'READY':'SETUP NEEDED'}</span></div>)}</div></>}
      </main>
    </div>
    {selected&&<div className="drawer-backdrop" onClick={()=>setSelected(null)}><aside className="finding-drawer" onClick={e=>e.stopPropagation()}><button className="drawer-close" onClick={()=>setSelected(null)}>Close ×</button><div className="mini-label">FINDING DETAIL / {selected.scanner.toUpperCase()}</div><span className={'severity-pill '+selected.severity}>{selected.severity}</span><h2>{selected.title}</h2><div className="drawer-section"><span>LOCATION</span><p>{selected.location||'No location provided'}</p></div><div className="drawer-section"><span>EVIDENCE</span><p>{selected.evidence}</p></div><div className="drawer-section"><span>CONFIDENCE</span><p>{selected.confidence}</p></div><div className="drawer-section"><span>HOW TO FIX</span><p>{selected.remediation}</p></div><div className="drawer-section"><span>VERIFY THE FIX</span><p>{selected.verification}</p></div><div className="drawer-rule">Rule: {selected.rule||'—'}</div>{["surface","tls","tls_config","dependencies","performance","journeys"].includes(selected.scanner)&&<div className="drawer-section"><span>OPTIONAL AI DRAFT</span>{assistantStatus?.external&&<label className="auth-confirm"><input type="checkbox" checked={allowExternal} onChange={e=>setAllowExternal(e.target.checked)}/><span>Send this selected finding to OpenRouter for an AI draft.</span></label>}<button type="button" className="export-button" disabled={draftBusy||!assistantStatus?.configured||(!!assistantStatus?.external&&!allowExternal)} onClick={()=>requestDraft(selected)}>{draftBusy?"Working…":`Draft with ${assistantStatus?.provider||"configured provider"}`}</button>{!assistantStatus?.configured&&<p>AI is off. Scanner fix guidance above remains available without a model or API key.</p>}{draftError&&<p>{draftError}</p>}{draft&&<div><p>{draft.summary}</p><ol>{draft.fix_steps.map((step,index)=><li key={index}>{step}</li>)}</ol><p>Verify: {draft.verification}</p><p>Uncertainty: {draft.uncertainty}</p><small>{draft.status} · {draft.model} · {draft.citation}</small></div>}</div>}</aside></div>}
  </div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
