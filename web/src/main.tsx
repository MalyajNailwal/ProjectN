import React, { useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, ArrowRight, BadgeCheck, Blocks, Boxes, ChevronRight, CircleAlert, CircleStop, Clock3, Cloud, Cpu, Database, Download, FileCode2, FileSearch, Fingerprint, FolderGit2, FolderOpen, Gauge, GitCompareArrows, Globe, Hash, History, KeyRound, LayoutDashboard, ListChecks, LoaderCircle, LockKeyhole, MapPin, Network, OctagonAlert, Radar, RotateCcw, Route, ScrollText, Shield, ShieldAlert, ShieldCheck, Sparkles, Trash2, Wrench, X, Zap } from 'lucide-react'
import { EmptyState, Meter, PageHeader, Panel, SeverityBadge, SeverityIcon, Stat, StateBadge, StateIcon, ThemeToggle, severityMeta, stateMeta } from './ui'
import './style.css'

type Scanner = {id:string;label:string;kind?:string;ready:boolean;source_present:boolean;limitations:string[];resolution:string|null;source_revision?:string|null;runtime_version?:string|null;runtime_origin?:string}
type Finding = {id:string;scanner:string;title:string;severity:string;location:string;evidence:string;remediation:string;rule:string;confidence:string;verification:string}
type Limitation = {code:string;message:string;resolution:string;scanner:string|null}
type Step = {id:string;label:string;state:string;summary?:string;started_at?:number;finished_at?:number}
type Stage = {id:string;label:string;state:string;summary:string;details?:Record<string,unknown>}
type Report = {target:{url:string|null;repo_url:string|null;local_path:string|null;commit:string|null};started_at:number;finished_at:number;cancelled?:boolean;steps?:Step[];findings:Finding[];stages:Stage[];limitations:Limitation[];summary:{findings:number;completed:number;incomplete:number}}
type ScanTarget = {url?:string|null;repo_url?:string|null;local_path?:string|null;journey_file?:string|null;api_spec_file?:string|null;oob_server?:string|null;oob_token_env?:string|null;profile?:string|null;port_depth?:string|null;port_range?:string|null;crawl_depth?:number|null;crawl_duration_minutes?:number|null;template_rate?:number|null;inventory_limit?:number|null;browser_page_limit?:number|null}
type Scan = {id:string;created:number;status:string;progress:string;target:ScanTarget;result:Report|null;error:string|null;steps?:Step[];finished?:number|null}
type ScanListItem = Pick<Scan,'id'|'created'|'status'|'progress'|'error'|'finished'> & {target:string}
type Comparison = {summary:{still_present:number;not_observed_on_rescan:number;not_verifiable:number;new:number}}
type RemediationDraft = {summary:string;fix_steps:string[];verification:string;uncertainty:string;citation:string;model:string;status:string}
type AssistantStatus = {provider:string;external:boolean;configured:boolean;mode:string}
type FullConfig = {port_depth:string;port_range:string;crawl_depth:number;crawl_duration_minutes:number;template_rate:number;inventory_limit:number;browser_page_limit:number}
type View = 'overview'|'findings'|'coverage'|'assets'|'setup'

const nav: {id:View;label:string;icon:React.ElementType;group:string}[] = [
  {id:'overview',label:'Overview',icon:LayoutDashboard,group:'Assessment'},
  {id:'coverage',label:'Coverage',icon:Radar,group:'Assessment'},
  {id:'findings',label:'Findings',icon:ShieldAlert,group:'Assessment'},
  {id:'assets',label:'Assets',icon:Boxes,group:'Assessment'},
  {id:'setup',label:'Tool setup',icon:Cpu,group:'System'},
]
const titles:Record<View,string> = {overview:'Overview',findings:'Findings',coverage:'Coverage',assets:'Assets',setup:'Tool setup'}
const views:View[] = ['overview','findings','coverage','assets','setup']
type Route = {view:View;scanId:string|null;findingId:string|null}
// Every page and open finding has its own URL, so browser Back and Forward move inside the app.
function readRoute():Route{
  const parts=window.location.pathname.split('/').filter(Boolean)
  const findingId=new URLSearchParams(window.location.search).get('finding')
  if(parts[0]==='scans'&&parts[1]) return {view:views.includes(parts[2] as View)?parts[2] as View:'overview',scanId:decodeURIComponent(parts[1]),findingId}
  return {view:views.includes(parts[0] as View)?parts[0] as View:'overview',scanId:null,findingId}
}
function routeUrl(view:View,scanId?:string|null,findingId?:string|null){
  const path=scanId&&view!=='setup'?`/scans/${encodeURIComponent(scanId)}${view==='overview'?'':`/${view}`}`:view==='overview'?'/':`/${view}`
  return findingId?`${path}?finding=${encodeURIComponent(findingId)}`:path
}
const plainClick = (event:React.MouseEvent) => event.button===0&&!event.metaKey&&!event.ctrlKey&&!event.shiftKey&&!event.altKey
const formatTime = (seconds:number) => new Date(seconds*1000).toLocaleString(undefined,{dateStyle:'medium',timeStyle:'short'})
const shortId = (id:string) => id.slice(0,8).toUpperCase()
const elapsed = (seconds:number) => {const s=Math.max(0,Math.round(seconds));return s<60?`${s}s`:s<3600?`${Math.floor(s/60)}m ${s%60}s`:`${Math.floor(s/3600)}h ${Math.floor(s%3600/60)}m`}
const clock = (seconds:number) => new Date(seconds*1000).toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})
const sameDay = (a:number,b:number) => new Date(a*1000).toDateString()===new Date(b*1000).toDateString()
// Start → end and duration for a scan; scans cut off before they finished show only when they started.
function timing(item:{created:number;finished?:number|null;status:string}){
  if(item.finished) return `${formatTime(item.created)} → ${sameDay(item.created,item.finished)?clock(item.finished):formatTime(item.finished)} · ${elapsed(item.finished-item.created)}`
  return `started ${formatTime(item.created)}${['queued','running'].includes(item.status)?' · running':''}`
}
const finishedStep = new Set(['completed','partial','failed','skipped'])
const stepWords:Record<string,string> = {pending:'Waiting',running:'Running now',skipped:'Skipped',cancelled:'Stopped by user',not_run:'Not run because the scan was stopped'}
const severityLevels = ['critical','high','medium','low','info','unknown']
const severityOrder:Record<string,number> = Object.fromEntries(severityLevels.map((level,index)=>[level,index]))
const builtinLabels:Record<string,string> = {surface:'HTTP surface',tls:'TLS connection',tls_config:'TLS configuration',api_spec:'API contract'}
const scannerGroups:[string,string,React.ElementType][] = [['web','Website scanners',Globe],['network','Network',Network],['code','Source code',FileCode2]]

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

function StatusBadge({status}:{status:string}){
  const meta=stateMeta[status]??{label:status,icon:CircleAlert}
  return <span className={`badge run-state ${status}`}><meta.icon size={13} className={status==='running'?'spin':undefined} aria-hidden="true"/>{meta.label}</span>
}

function Fact({icon:Icon,label,children}:{icon:React.ElementType;label:string;children:React.ReactNode}){
  return <div className="fact"><dt><Icon size={14} aria-hidden="true"/>{label}</dt><dd>{children}</dd></div>
}

function App(){
  const [view,setView] = useState<View>(()=>readRoute().view)
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
  const [portDepth,setPortDepth] = useState<'quick'|'standard'|'thorough'|'full'|'custom'>('standard')
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
  const [rerunSourceId,setRerunSourceId] = useState<string|null>(null)
  const [selected,setSelected] = useState<Finding|null>(null)
  const [severity,setSeverity] = useState('all')
  const [comparison,setComparison] = useState<Comparison|null>(null)
  const [draft,setDraft] = useState<RemediationDraft|null>(null)
  const [findingHistory,setFindingHistory] = useState<{first_seen:number|null;seen_in_scans:number}|null>(null)
  const [draftError,setDraftError] = useState('')
  const [draftBusy,setDraftBusy] = useState(false)
  const [assistantStatus,setAssistantStatus] = useState<AssistantStatus|null>(null)
  const [allowExternal,setAllowExternal] = useState(false)
  const [stopping,setStopping] = useState(false)
  const [confirmClear,setConfirmClear] = useState(false)
  const [confirmDelete,setConfirmDelete] = useState<string|null>(null)
  const [now,setNow] = useState(()=>Date.now()/1000)
  const closeButton = useRef<HTMLButtonElement>(null)
  const scanForm = useRef<HTMLElement>(null)
  const active = !!scan && ['queued','running'].includes(scan.status)
  const scanRef = useRef(scan)
  scanRef.current = scan
  function go(next:View,options:{scanId?:string|null;finding?:string|null;replace?:boolean}={}){
    const url=routeUrl(next,options.scanId!==undefined?options.scanId:scanRef.current?.id??null,options.finding??null)
    if(url!==window.location.pathname+window.location.search) window.history[options.replace?'replaceState':'pushState']({projectn:true},'',url)
    setView(next)
    window.scrollTo({top:0})
  }
  function link(next:View){
    return {href:routeUrl(next,scan?.id),onClick:(event:React.MouseEvent)=>{if(plainClick(event)){event.preventDefault();go(next)}}}
  }
  function selectFinding(item:Finding){
    setSelected(item);setDraft(null);setDraftError('');setAllowExternal(false)
    go(view,{finding:item.id})
  }
  function closeFinding(){
    if(readRoute().findingId&&window.history.state?.projectn) window.history.back()
    else{setSelected(null);go(view,{replace:true})}
  }

  useEffect(()=>{
    setFindingHistory(null)
    if(selected&&scan) jsonFetch<{first_seen:number|null;seen_in_scans:number}>(`/api/scans/${scan.id}/findings/${selected.id}/history`).then(setFindingHistory).catch(()=>{})
  },[selected?.id,scan?.id])
  useEffect(()=>{
    jsonFetch<Scanner[]>('/api/scanners').then(setScanners).catch(e=>setError(e.message))
    jsonFetch<AssistantStatus>('/api/assistant/status').then(setAssistantStatus).catch(()=>{})
    jsonFetch<FullConfig>('/api/config/full').then(setFullDefaults).catch(e=>setError(e.message))
    const route=readRoute()
    jsonFetch<ScanListItem[]>('/api/scans').then(items=>{
      setHistory(items)
      const id=route.scanId??items[0]?.id
      if(id) jsonFetch<Scan>(`/api/scans/${id}`).then(setScan).catch(()=>route.scanId?setError(`Scan ${shortId(route.scanId)} was not found in local history.`):undefined)
    }).catch(e=>setError(e.message))
    const onPop=()=>{
      const next=readRoute()
      setView(next.view)
      if(next.scanId&&next.scanId!==scanRef.current?.id) jsonFetch<Scan>(`/api/scans/${next.scanId}`).then(setScan).catch(e=>setError(e.message))
      setSelected(next.findingId?scanRef.current?.result?.findings.find(item=>item.id===next.findingId)??null:null)
    }
    window.addEventListener('popstate',onPop)
    return ()=>window.removeEventListener('popstate',onPop)
  },[])
  useEffect(()=>{
    const id=readRoute().findingId
    if(id&&scan?.result) setSelected(scan.result.findings.find(item=>item.id===id)??null)
  },[scan?.id,scan?.result])
  useEffect(()=>{
    if(!selected) return
    closeButton.current?.focus()
    const onKey=(event:KeyboardEvent)=>{if(event.key==='Escape') closeFinding()}
    window.addEventListener('keydown',onKey)
    return ()=>window.removeEventListener('keydown',onKey)
  },[selected])
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
  const counts=useMemo(()=>{const result:Record<string,number>={};for(const item of report?.findings||[]) result[item.severity]=(result[item.severity]||0)+1;return result},[report])
  const urgent=(counts.critical||0)+(counts.high||0)
  const filtered=useMemo(()=>[...(report?.findings||[])].filter(f=>severity==='all'||f.severity===severity).sort((a,b)=>(severityOrder[a.severity]??6)-(severityOrder[b.severity]??6)),[report,severity])
  const scannerLabel=(id:string)=>scanners.find(item=>item.id===id)?.label||builtinLabels[id]||id
  const detail=<T,>(id:string,key:string)=>report?.stages.find(s=>s.id===id)?.details?.[key] as T|undefined
  const ports=detail<{host:string;port:number;protocol:string;state:string;service:string;version:string}[]>('ports','ports')
  const urls=detail<string[]>('crawler','urls')
  const apiEndpoints=detail<{method:string;url:string;status:number|null;content_type:string}[]>('crawler','api_endpoints')
  const renderedPages=detail<{url:string;title:string;status:number|null}[]>('browser','pages')
  const renderedForms=detail<{page:string;action:string;method:string;fields:{name:string;type:string}[]}[]>('browser','forms')
  const browserApis=detail<{method:string;url:string;status:number|null}[]>('browser','api_endpoints')
  const apiContract=report?.stages.find(s=>s.id==='api_spec')?.details as {declared?:{method:string;path:string;observed:boolean}[];undocumented_observed?:{method:string;url:string}[]}|undefined
  const journeyResults=detail<{name:string;covers:string[];passed:boolean;completed_steps:number;issues:{step:number;type:string}[]}[]>('journeys','journeys')
  const performanceScores=detail<Record<string,{title:string;score:number|null}>>('performance','categories')
  const tlsDetails=report?.stages.find(s=>s.id==='tls')?.details as {protocol?:string;cipher?:string;days_until_expiry?:number}|undefined
  const technologies=detail<string[]>('technology','technologies')
  type InfraMatch={id:string;label:string;match_percent:number;confidence:string;evidence:string[]}
  const infraHosting=detail<InfraMatch[]>('infra','hosting')
  const infraBaas=detail<InfraMatch[]>('infra','baas')
  const infraFrameworks=detail<InfraMatch[]>('infra','frameworks')
  const navBadge:Partial<Record<View,string|number>>={findings:report?report.findings.length:undefined,coverage:report?.limitations.length||undefined,setup:scanners.length?`${ready}/${scanners.length}`:undefined}
  const exportButton=report&&scan?<a className="btn secondary" href={`/api/scans/${scan.id}/export`}><Download size={15} aria-hidden="true"/>Export JSON</a>:undefined
  const targetOf=(target:{url?:string|null;repo_url?:string|null;local_path?:string|null})=>target.url||target.repo_url||target.local_path||'Target pending'

  function prepareRerun(){
    if(!scan||active) return
    const target=scan.target
    setUrl(target.url??'')
    setRepo(target.repo_url??'')
    setFolder(target.local_path??'')
    setJourneyFile(target.journey_file??'')
    setApiSpecFile(target.api_spec_file??'')
    setOobServer(target.oob_server??'')
    setOobTokenEnv(target.oob_token_env??'')
    setProfile(target.profile==='full'||target.profile==='deep'?target.profile:'standard')
    setAuthorized(false)
    setPortDepth(target.port_depth==='quick'||target.port_depth==='thorough'||target.port_depth==='full'||target.port_depth==='custom'?target.port_depth:target.port_range?'custom':'standard')
    setPortRange(target.port_range??'')
    setCrawlDepth(String(target.crawl_depth??''))
    setCrawlMinutes(String(target.crawl_duration_minutes??''))
    setTemplateRate(String(target.template_rate??''))
    setInventoryLimit(String(target.inventory_limit??''))
    setBrowserPageLimit(String(target.browser_page_limit??''))
    setSubmitError('')
    setSubmittedScanId(null)
    setRerunSourceId(scan.id)
    go('overview',{scanId:scan.id})
    window.requestAnimationFrame(()=>scanForm.current?.scrollIntoView({behavior:'smooth',block:'start'}))
  }

  async function submit(event:React.FormEvent){
    event.preventDefault();setError('');setSubmitError('');setBusy(true)
    try{
      const fullOptions=profile==='full'?{port_depth:portDepth,port_range:portDepth==='custom'?(portRange.trim()||null):null,crawl_depth:crawlDepth?Number(crawlDepth):null,crawl_duration_minutes:crawlMinutes?Number(crawlMinutes):null,template_rate:templateRate?Number(templateRate):null,inventory_limit:inventoryLimit?Number(inventoryLimit):null,browser_page_limit:browserPageLimit?Number(browserPageLimit):null}:{}
      const enteredUrl=url.trim()
      const normalizedUrl=enteredUrl&&!enteredUrl.includes('://')?`https://${enteredUrl}`:enteredUrl
      const result=await jsonFetch<{id:string}>('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:normalizedUrl||null,repo_url:repo.trim()||null,local_path:folder.trim()||null,journey_file:profile==='full'?journeyFile.trim()||null:null,api_spec_file:apiSpecFile.trim()||null,oob_server:profile==='full'?oobServer.trim()||null:null,oob_token_env:profile==='full'?oobTokenEnv.trim()||null:null,profile,authorized_intrusive:authorized,...fullOptions})})
      setScan({id:result.id,created:Date.now()/1000,status:'queued',progress:'Waiting to start',target:{url:normalizedUrl,repo_url:repo,local_path:folder},result:null,error:null})
      setSubmittedScanId(result.id)
      setRerunSourceId(null)
      go('overview',{scanId:result.id})
      const items=await jsonFetch<ScanListItem[]>('/api/scans');setHistory(items)
    }catch(e){setSubmitError((e as Error).message)}finally{setBusy(false)}
  }
  async function stopScan(){
    if(!scan) return
    setStopping(true)
    try{await jsonFetch(`/api/scans/${scan.id}/cancel`,{method:'POST'})}catch(e){setError((e as Error).message);setStopping(false)}
  }
  async function openScan(id:string,next:View='overview'){
    setError('');setSelected(null)
    try{setScan(await jsonFetch<Scan>(`/api/scans/${id}`));go(next,{scanId:id})}catch(e){setError((e as Error).message)}
  }
  async function removeScans(id?:string){
    setError('')
    try{
      await jsonFetch(id?`/api/scans/${id}`:'/api/scans',{method:'DELETE'})
      const items=await jsonFetch<ScanListItem[]>('/api/scans')
      setHistory(items)
      if(scan&&!items.some(item=>item.id===scan.id)){setScan(null);setSelected(null);go('overview',{scanId:null,replace:true})}
    }catch(e){setError((e as Error).message)}
    finally{setConfirmClear(false);setConfirmDelete(null)}
  }
  async function requestDraft(item:Finding){
    if(!scan) return
    setDraft(null);setDraftError('');setDraftBusy(true)
    try{setDraft(await jsonFetch<RemediationDraft>(`/api/scans/${scan.id}/findings/${item.id}/draft`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({allow_external:allowExternal})}))}
    catch(e){setDraftError((e as Error).message)}finally{setDraftBusy(false)}
  }

  const profiles:{id:'standard'|'deep'|'full';title:string;text:string;icon:React.ElementType}[]=[
    {id:'standard',title:'Standard',text:'Discovery and inventory',icon:Shield},
    {id:'deep',title:'Deep',text:'Adds template-based vulnerability checks',icon:Zap},
    {id:'full',title:'Full scope',text:'All TCP ports, JavaScript crawl, ZAP, axe, Lighthouse',icon:Radar},
  ]

  const overview=<>
    <PageHeader title="Security overview" description="Assess a website you are authorized to test, a local folder, or a public repository. Every report shows its evidence, and what was not covered."
      actions={<div className="trust"><span><BadgeCheck size={14} aria-hidden="true"/>Evidence first</span><span><LockKeyhole size={14} aria-hidden="true"/>Runs locally</span><span><GitCompareArrows size={14} aria-hidden="true"/>Rescan verification</span></div>}/>
    <div className="stats">
      <Stat label="Findings" icon={ShieldAlert} value={report?report.findings.length:'—'} hint={report?<span className="sev-bar" aria-label="Findings by severity">{severityLevels.map(level=>counts[level]?<span key={level} className={`sev-${level}`} style={{flex:counts[level]}} title={`${counts[level]} ${level}`}/>:null)}</span>:'No report selected'}/>
      <Stat label="Critical and high" icon={OctagonAlert} tone={urgent?'danger':undefined} value={report?urgent:'—'} hint={report?(urgent?'Fix these first':'None in this report'):'—'}/>
      <Stat label="Stages completed" icon={ListChecks} value={report?`${report.summary.completed}/${report.stages.length}`:'—'} hint={report?`${report.limitations.length} coverage gaps to review`:'—'}/>
      <Stat label="Scanners ready" icon={Cpu} tone={scanners.length&&ready<scanners.length?'warn':undefined} value={scanners.length?`${ready}/${scanners.length}`:'—'} hint={scanners.length?(ready===scanners.length?'All capabilities available':'Some checks need setup'):'Checking…'}/>
    </div>
    <div className="overview-grid">
      <section className="card scan-card" ref={scanForm}>
        <div className="card-head"><h2>Start a scan</h2><span className="hint-text">Website, source, or both</span></div>
        {rerunSourceId&&<div className="notice info" role="status">Settings from scan #{shortId(rerunSourceId)} are ready. Review the target and launch a new assessment.</div>}
        <form onSubmit={submit}>
          <label className="field"><span className="field-label">Website URL</span><span className="input"><Globe size={16} aria-hidden="true"/><input id="website" value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://your-site.com" autoComplete="url"/></span></label>
          <div className="divider"><span>and / or</span></div>
          <div className="field-pair">
            <label className="field"><span className="field-label">Public GitHub repository</span><span className="input"><FolderGit2 size={16} aria-hidden="true"/><input id="repo" value={repo} onChange={e=>setRepo(e.target.value)} placeholder="https://github.com/owner/repository"/></span></label>
            <label className="field"><span className="field-label">Or a local folder</span><span className="input"><FolderOpen size={16} aria-hidden="true"/><input id="folder" value={folder} onChange={e=>setFolder(e.target.value)} placeholder="/path/to/project"/></span></label>
          </div>
          <label className="field"><span className="field-label">OpenAPI file <em>optional</em></span><span className="input"><FileCode2 size={16} aria-hidden="true"/><input id="api-spec" value={apiSpecFile} onChange={e=>setApiSpecFile(e.target.value)} placeholder="/path/to/openapi.yaml"/></span></label>
          <fieldset className="profiles"><legend className="field-label">Scan profile</legend>{profiles.map(item=><button type="button" key={item.id} className={'profile'+(profile===item.id?' on':'')} aria-pressed={profile===item.id} onClick={()=>setProfile(item.id)}><item.icon size={16} aria-hidden="true"/><span><strong>{item.title}</strong><small>{item.text}</small></span></button>)}</fieldset>
          {profile==='full'&&<div className="full-options">
            <p className="field-label">Full scan limits <em>blank uses config/full_scan.json</em></p>
            <div className="port-depth-row">
              <span className="field-label">Port scan depth</span>
              <div className="port-depth-options">
                {([['quick','Quick','top 100, seconds'],['standard','Standard','top 1000, recommended'],['thorough','Thorough','top 5000'],['full','All 65535','can take hours'],['custom','Custom range','set it below']] as const).map(([id,label,hint])=>
                  <button type="button" key={id} className={'depth-chip'+(portDepth===id?' on':'')} aria-pressed={portDepth===id} onClick={()=>setPortDepth(id)}><strong>{label}</strong><small>{hint}</small></button>
                )}
              </div>
            </div>
            <div className="option-grid">
              {portDepth==='custom'&&<label>TCP ports<input value={portRange} onChange={e=>setPortRange(e.target.value)} placeholder={fullDefaults?.port_range||''}/></label>}
              <label>Crawl depth<input type="number" min="1" value={crawlDepth} onChange={e=>setCrawlDepth(e.target.value)} placeholder={String(fullDefaults?.crawl_depth??'')}/></label>
              <label>Crawl minutes<input type="number" min="1" value={crawlMinutes} onChange={e=>setCrawlMinutes(e.target.value)} placeholder={String(fullDefaults?.crawl_duration_minutes??'')}/></label>
              <label>Template requests/sec<input type="number" min="1" value={templateRate} onChange={e=>setTemplateRate(e.target.value)} placeholder={String(fullDefaults?.template_rate??'')}/></label>
              <label>Report endpoints<input type="number" min="1" value={inventoryLimit} onChange={e=>setInventoryLimit(e.target.value)} placeholder={String(fullDefaults?.inventory_limit??'')}/></label>
              <label>Rendered pages<input type="number" min="1" value={browserPageLimit} onChange={e=>setBrowserPageLimit(e.target.value)} placeholder={String(fullDefaults?.browser_page_limit??'')}/></label>
            </div>
            {url.trim()&&<label className="wide-field">Journey JSON file <span>Credentials come from local environment variables</span><input value={journeyFile} onChange={e=>setJourneyFile(e.target.value)} placeholder="/path/to/journeys.json"/></label>}
            {url.trim()&&<label className="wide-field">Self-hosted OOB callback HTTPS origin <span>Must be reachable by the target</span><input value={oobServer} onChange={e=>setOobServer(e.target.value)} placeholder="https://callback.example.com"/></label>}
            {url.trim()&&oobServer.trim()&&<label className="wide-field">Callback token environment variable <span>The token stays local</span><input value={oobTokenEnv} onChange={e=>setOobTokenEnv(e.target.value)} placeholder="PROJECTN_OOB_TOKEN"/></label>}
          </div>}
          {profile==='full'&&url.trim()&&<label className="consent"><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)}/><span>I am authorized to run intrusive checks against this website.</span></label>}
          <button className="btn primary block" disabled={busy||(!url.trim()&&!repo.trim()&&!folder.trim())||(profile==='full'&&!!url.trim()&&!authorized)}>{busy?<><LoaderCircle size={16} className="spin" aria-hidden="true"/>Preparing scan…</>:<>Launch assessment<ArrowRight size={16} aria-hidden="true"/></>}</button>
          {submitError&&<div className="notice error" role="alert"><CircleAlert size={15} aria-hidden="true"/>{submitError}</div>}
          {submittedScanId===scan?.id&&<div className="notice info" role="status">Scan #{shortId(scan.id)} {stateMeta[scan.status]?.label.toLowerCase()??scan.status}{steps.length>0&&` · ${percent}%`} · {currentStep?.label||scan.progress}</div>}
          <p className="fine-print"><LockKeyhole size={13} aria-hidden="true"/>Scan only sites and systems you are authorized to assess.</p>
        </form>
      </section>
      <div className="side-stack">
        <section className="card run-card">
          <div className="card-head"><h2>Current assessment</h2>{scan&&<StatusBadge status={scan.status}/>}</div>
          {scan?<>
            <div className="run-meta"><code>#{shortId(scan.id)}</code>{active&&<span className="run-clock"><Activity size={13} aria-hidden="true"/>{elapsed(now-scan.created)}</span>}{!active&&scan.finished&&<span className="run-clock" title={timing(scan)}><Clock3 size={13} aria-hidden="true"/>took {elapsed(scan.finished-scan.created)}</span>}</div>
            {steps.length>0&&<div className="run-progress"><div className="run-progress-head"><strong>{percent}%</strong><span>{doneSteps} of {steps.length} steps finished</span></div><Meter value={percent} label="Scan progress"/></div>}
            <p className="run-now" aria-live="polite">{currentStep?<><LoaderCircle size={14} className="spin" aria-hidden="true"/>{currentStep.label}<span>{elapsed(now-(currentStep.started_at||now))}</span></>:scan.progress}</p>
            <div className="run-target" title={targetOf(scan.target)}><Globe size={14} aria-hidden="true"/>{targetOf(scan.target)}</div>
            {active&&<button type="button" className="btn danger block" onClick={stopScan} disabled={stopping}><CircleStop size={15} aria-hidden="true"/>{stopping?'Stopping scanners…':'Stop scan'}</button>}
            {scan.status==='failed'&&scan.error&&<div className="notice error"><CircleAlert size={15} aria-hidden="true"/>{scan.error}</div>}
            {scan.result&&<button className="btn secondary block" onClick={()=>go('findings')}>{scan.status==='cancelled'?'Explore partial report':'Explore report'}<ArrowRight size={15} aria-hidden="true"/></button>}
            {!active&&steps.length===0&&<button type="button" className="btn secondary block" onClick={prepareRerun}><RotateCcw size={15} aria-hidden="true"/>Run again</button>}
          </>:<EmptyState icon={Radar} title="No scans yet">Start an assessment to build a local history of findings and coverage.</EmptyState>}
        </section>
        <section className="card readiness-card">
          <div className="card-head"><h2>Scanner readiness</h2><a className="text-link" {...link('setup')}>Details<ChevronRight size={14} aria-hidden="true"/></a></div>
          <div className="readiness"><strong>{scanners.length?ready:'—'}</strong><span>of {scanners.length||'—'} capabilities ready</span></div>
          <Meter value={scanners.length?Math.round(ready/scanners.length*100):0} label="Scanner readiness"/>
        </section>
      </div>
    </div>
    {steps.length>0&&<section className="card steps-section">
      <div className="card-head"><h2>{active?'What is happening now':'What ran'}</h2><div className="head-actions"><span className="hint-text">{doneSteps} of {steps.length} finished · #{shortId(scan!.id)}</span>{!active&&<button type="button" className="btn ghost sm" onClick={prepareRerun}><RotateCcw size={14} aria-hidden="true"/>Run again</button>}</div></div>
      <ol className="step-list">{steps.map(step=>{const seconds=step.started_at?(step.finished_at||now)-step.started_at:null;return <li key={step.id} className={'step '+step.state}><StateIcon state={step.state}/><span className="step-label"><strong>{step.label}</strong><small>{step.summary||stepWords[step.state]||step.state}</small></span><span className="step-time">{seconds===null?'':elapsed(seconds)}</span></li>})}</ol>
    </section>}
    <section className="card history">
      <div className="card-head"><h2><History size={16} aria-hidden="true"/>Recent scans</h2><div className="head-actions"><span className="hint-text">{history.length} stored on this computer</span>{history.some(item=>!['queued','running'].includes(item.status))&&(confirmClear
        ?<span className="confirm" role="group" aria-label="Confirm clearing history"><span>Delete all finished scans?</span><button type="button" className="btn ghost sm" onClick={()=>setConfirmClear(false)}>Cancel</button><button type="button" className="btn danger sm" onClick={()=>removeScans()}><Trash2 size={14} aria-hidden="true"/>Delete</button></span>
        :<button type="button" className="btn ghost sm" onClick={()=>setConfirmClear(true)}><Trash2 size={14} aria-hidden="true"/>Clear history</button>)}</div></div>
      {history.length?<div className="rows scroll">{history.map(item=>{let target:Record<string,string|null>={};try{target=JSON.parse(item.target)}catch{/* older rows may hold invalid JSON */}const running=['queued','running'].includes(item.status);const hasReport=['completed','cancelled'].includes(item.status);const body=<><StateIcon state={item.status}/><span className="row-main"><strong>{target.url||target.repo_url||target.local_path||'Unknown target'}</strong><small><code>#{shortId(item.id)}</code> · {timing(item)}</small>{item.status==='failed'&&<small className="row-error">{item.error||item.progress||'The scan stopped with an error before producing a report.'}</small>}</span><StatusBadge status={item.status}/></>;return <div key={item.id} className={'row-wrap'+(scan?.id===item.id?' current':'')}>
        {hasReport||running
          ?<button className="row" onClick={()=>openScan(item.id,hasReport?'findings':'overview')}>{body}<span className="row-cta">{hasReport?'View report':'View progress'}<ChevronRight size={15} aria-hidden="true"/></span></button>
          :<div className="row static">{body}</div>}
        {!running&&(confirmDelete===item.id
          ?<span className="confirm" role="group" aria-label={`Confirm deleting scan #${shortId(item.id)}`}><button type="button" className="btn ghost sm" onClick={()=>setConfirmDelete(null)}>Cancel</button><button type="button" className="btn danger sm" onClick={()=>removeScans(item.id)}>Delete</button></span>
          :<button type="button" className="icon-btn ghost" aria-label={`Delete scan #${shortId(item.id)}`} title="Delete this scan" onClick={()=>setConfirmDelete(item.id)}><Trash2 size={15} aria-hidden="true"/></button>)}
      </div>})}</div>:<EmptyState icon={History} title="Your first scan will appear here"/>}
    </section>
  </>

  const findingsView=<>
    <PageHeader title="Findings" description="Observed issues with their evidence, severity, and the steps to fix and verify them." actions={exportButton}/>
    {comparison&&<div className="callout"><GitCompareArrows size={18} aria-hidden="true"/><div><strong>Rescan comparison</strong><span>{comparison.summary.still_present} still present · {comparison.summary.not_observed_on_rescan} not observed on rescan · {comparison.summary.not_verifiable} not verifiable · {comparison.summary.new} new</span></div></div>}
    <div className="finding-toolbar" role="toolbar" aria-label="Filter findings by severity">
      <button type="button" className={'chip'+(severity==='all'?' on':'')} aria-pressed={severity==='all'} onClick={()=>setSeverity('all')}>All<span className="chip-count">{report?.findings.length??0}</span></button>
      {severityLevels.filter(level=>counts[level]).map(level=><button type="button" key={level} className={`chip sev-${level}`+(severity===level?' on':'')} aria-pressed={severity===level} onClick={()=>setSeverity(level)}><SeverityIcon level={level}/>{severityMeta[level].label}<span className="chip-count">{counts[level]}</span></button>)}
    </div>
    {filtered.length?<div className="card list scroll tall">{filtered.map(item=><button key={item.id} className="finding-row" onClick={()=>selectFinding(item)}><SeverityIcon level={item.severity}/><span className="row-main"><strong>{item.title}</strong><span className="row-meta"><span className="tag">{scannerLabel(item.scanner)}</span>{item.location&&<code>{item.location}</code>}</span></span><SeverityBadge level={item.severity}/><ChevronRight size={16} aria-hidden="true"/></button>)}</div>
      :<div className="card"><EmptyState icon={ShieldCheck} title={report?'No findings in this view':'No report selected'}>{report?'Zero findings is not proof of safety. Check Coverage to see which checks completed and which need another run.':'Start a scan from Overview to generate findings.'}</EmptyState></div>}
  </>

  const coverageView=<>
    <PageHeader title="Coverage" description="What ran, what did not, and the concrete next step for each gap." actions={exportButton}/>
    <div className="stats three">
      <Stat label="Completed stages" icon={ListChecks} value={report?.summary.completed??'—'}/>
      <Stat label="Incomplete stages" icon={CircleAlert} tone={report?.summary.incomplete?'warn':undefined} value={report?.summary.incomplete??'—'}/>
      <Stat label="Coverage gaps" icon={Route} value={report?.limitations.length??'—'}/>
    </div>
    <div className="two-col">
      <Panel title="Scanner stages" icon={ListChecks} meta={report?`${report.stages.length} stages`:undefined}>
        {report?.stages.length?<div className="rows scroll tall">{report.stages.map(stage=><div key={stage.id} className="stage-row"><StateIcon state={stage.state}/><span className="row-main"><strong>{stage.label}</strong><small>{stage.summary}</small>{typeof stage.details?.diagnostic==='string'&&stage.details.diagnostic&&<details className="diagnostic"><summary>Scanner output</summary><pre>{stage.details.diagnostic}</pre></details>}</span><StateBadge state={stage.state}/></div>)}</div>:<EmptyState icon={ListChecks} title="No stages recorded yet"/>}
      </Panel>
      <Panel title="Coverage gaps" icon={Route} meta={report?`${report.limitations.length} to review`:undefined}>
        {report?.limitations.length?<ol className="gaps scroll tall">{report.limitations.map((item,index)=><li key={`${item.code}-${index}`}><span className="gap-number">{String(index+1).padStart(2,'0')}</span><div><strong>{item.message}</strong><p>{item.resolution}</p>{item.scanner&&<span className="tag">{item.scanner.split(', ').map(scannerLabel).join(', ')}</span>}</div></li>)}</ol>:<EmptyState icon={BadgeCheck} title="No limitations recorded">This scan reported no coverage gaps.</EmptyState>}
      </Panel>
    </div>
  </>

  function InfraGroup({icon:Icon,title,items,empty}:{icon:React.ElementType;title:string;items?:InfraMatch[];empty:string}){
  return <div className="infra-group"><h3><Icon size={14} aria-hidden="true"/>{title}</h3>{items?.length?<div className="infra-list">{items.map(item=><div className="infra-match" key={item.id}><div className="infra-match-head"><strong>{item.label}</strong><span className={'badge infra-conf '+item.confidence}>{item.match_percent}% match</span></div><small>{item.evidence.join(' · ')}</small></div>)}</div>:<p className="muted">{empty}</p>}</div>
}
const assetsView=<>
    <PageHeader title="Assets" description="What this assessment actually observed. Counts cover the scoped scan only, not a complete inventory." actions={exportButton}/>
    {(infraHosting||infraBaas||infraFrameworks)&&<Panel title="Infrastructure & stack" icon={Cloud} meta="from the fetched homepage">
      <p className="infra-note">Each percent is the share of known signals matched for that provider (shown below it), not an estimated probability. Homepage only; an unlisted or custom-built stack will not be detected.</p>
      <div className="infra-columns">
        <InfraGroup icon={Cloud} title="Hosting & CDN" items={infraHosting} empty="No known hosting or CDN signals matched."/>
        <InfraGroup icon={Database} title="Backend & auth" items={infraBaas} empty="No known backend-as-a-service signals matched."/>
        <InfraGroup icon={Blocks} title="Frontend framework" items={infraFrameworks} empty="No known frontend framework signals matched."/>
      </div>
    </Panel>}
    <div className="two-col">
      <Panel title="Ports and services" icon={Network} meta={ports?.length?`${ports.length} recorded`:undefined}>
        {ports?.length?<div className="rows scroll">{ports.map((port,index)=><div className="asset-row" key={`${port.host}-${port.port}-${index}`}><code className="port">{port.port}<small>/{port.protocol}</small></code><span className="row-main"><strong>{port.service}{port.version&&` ${port.version}`}</strong><small>{port.host}</small></span><span className={`badge port-${port.state}`}>{port.state}</span></div>)}</div>:<EmptyState icon={Network} title="No port inventory">Check scanner setup and the Coverage page.</EmptyState>}
      </Panel>
      <Panel title="Discovered routes" icon={Route} meta={urls?.length?`${urls.length} routes`:undefined}>
        {urls?.length?<ul className="mono-list scroll">{urls.map((route,index)=><li key={`${route}-${index}`}><code>{route}</code></li>)}</ul>:<EmptyState icon={Route} title="No routes recorded">Check crawler status and target access.</EmptyState>}
      </Panel>
      <Panel title="JSON endpoints" icon={FileCode2}>
        {apiEndpoints?.length?<ul className="mono-list scroll">{apiEndpoints.map((item,index)=><li key={`${item.method}-${item.url}-${index}`}><span className="method">{item.method}</span><code>{item.url}</code><span className="status-code">{item.status??'?'}</span></li>)}</ul>:<EmptyState icon={FileCode2} title="No JSON endpoints observed">This is not a complete API count.</EmptyState>}
      </Panel>
      <Panel title="Rendered pages and forms" icon={Globe}>
        {renderedPages?.length?<ul className="mono-list scroll">{renderedPages.map((item,index)=><li key={`${item.url}-${index}`}><span className="status-code">{item.status??'?'}</span><span className="grow">{item.title||item.url}</span><code>{item.url}</code></li>)}{renderedForms?.map((item,index)=><li key={`${item.page}-form-${index}`}><span className="method">{item.method}</span><span className="grow">Form → {item.action}</span><code>{item.fields.map(field=>field.type).join(', ')}</code></li>)}</ul>:<EmptyState icon={Globe} title="No rendered-page inventory">Runs in Full scope with the browser runtime ready.</EmptyState>}
      </Panel>
      <Panel title="Browser API traffic" icon={Activity}>
        {browserApis?.length?<ul className="mono-list scroll">{browserApis.map((item,index)=><li key={`${item.method}-${item.url}-${index}`}><span className="method">{item.method}</span><code>{item.url}</code><span className="status-code">{item.status??'?'}</span></li>)}</ul>:<EmptyState icon={Activity} title="No JSON responses observed in rendered pages"/>}
      </Panel>
      <Panel title="Configured journeys" icon={KeyRound}>
        {journeyResults?.length?<div className="rows scroll">{journeyResults.map((item,index)=><div className="asset-row" key={`${item.name}-${index}`}><StateIcon state={item.passed?'completed':'partial'}/><span className="row-main"><strong>{item.name}</strong><small>{item.completed_steps} steps · {item.covers.join(', ')||'coverage unspecified'}{item.issues.length?` · ${item.issues.map(issue=>issue.type).join(', ')}`:''}</small></span><StateBadge state={item.passed?'completed':'partial'}/></div>)}</div>:<EmptyState icon={KeyRound} title="No account journey configured">Add a journey file with test accounts in Full scope.</EmptyState>}
      </Panel>
      <Panel title="TLS and page quality" icon={Gauge}>
        {tlsDetails?.protocol&&<div className="asset-row"><LockKeyhole size={16} aria-hidden="true"/><span className="row-main"><strong>{tlsDetails.protocol}</strong><small>{tlsDetails.cipher} · certificate {tlsDetails.days_until_expiry} days remaining</small></span></div>}
        {performanceScores&&<div className="scores">{Object.entries(performanceScores).map(([key,item])=><div key={key} className="score"><span>{item.title||key}</span><strong>{item.score==null?'—':Math.round(item.score*100)}</strong><Meter value={item.score==null?0:Math.round(item.score*100)} label={`${item.title||key} score`}/></div>)}</div>}
        {!tlsDetails?.protocol&&!performanceScores&&<EmptyState icon={Gauge} title="No TLS or Lighthouse measurements"/>}
      </Panel>
      <Panel title="API contract" icon={ScrollText}>
        {apiContract?.declared?.length?<ul className="mono-list scroll">{apiContract.declared.map((item,index)=><li key={`${item.method}-${item.path}-${index}`}><span className="method">{item.method}</span><code>{item.path}</code><span className={'badge '+(item.observed?'state-completed':'state-skipped')}>{item.observed?'Observed':'Not observed'}</span></li>)}{apiContract.undocumented_observed?.map((item,index)=><li key={`${item.method}-${item.url}-${index}`}><span className="method">{item.method}</span><code>{item.url}</code><span className="badge state-partial">Not in spec</span></li>)}</ul>:<EmptyState icon={ScrollText} title="No OpenAPI contract supplied"/>}
      </Panel>
    </div>
    <Panel title="Technologies" icon={Fingerprint}>
      {technologies?.length?<div className="chips scroll short">{technologies.map(item=><span className="tag" key={item}>{item}</span>)}</div>:<EmptyState icon={Fingerprint} title="No technology profile available"/>}
    </Panel>
  </>

  const setupView=<>
    <PageHeader title="Tool setup" description="Each scanner needs its pinned upstream source and a local runtime. A missing tool is reported as a coverage gap, never as a pass."
      actions={<div className="tally"><strong>{scanners.length?ready:'—'}<span>/{scanners.length||'—'}</span></strong><small>ready</small></div>}/>
    {scannerGroups.map(([kind,title,icon])=>{const group=scanners.filter(tool=>(tool.kind||'web')===kind);if(!group.length) return null;return <Panel key={kind} title={title} icon={icon} meta={`${group.filter(tool=>tool.ready).length}/${group.length} ready`}>
      <div className="rows">{group.map(tool=><div className="setup-row" key={tool.id}><StateIcon state={tool.ready?'completed':'failed'}/><span className="row-main"><strong>{tool.label}</strong>{tool.ready?<span className="row-meta">{tool.runtime_origin&&<span className="tag">{tool.runtime_origin}</span>}{tool.runtime_version&&<code>runtime {tool.runtime_version}</code>}{tool.source_revision&&<code>source {tool.source_revision.slice(0,10)}</code>}</span>:<><small>{tool.limitations.join(' · ')}</small>{tool.resolution&&<code className="fix">{tool.resolution}</code>}</>}</span><span className={'badge '+(tool.ready?'state-completed':'state-partial')}>{tool.ready?'Ready':'Setup needed'}</span></div>)}</div>
    </Panel>})}
  </>

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" {...link('overview')}><span className="brand-mark"><ShieldCheck size={18} aria-hidden="true"/></span><span><strong>ProjectN</strong><small>Security workstation</small></span></a>
      <nav className="nav" aria-label="Main">{['Assessment','System'].map(group=><div className="nav-group" key={group}><span className="nav-heading">{group}</span>{nav.filter(item=>item.group===group).map(item=><a key={item.id} className={'nav-item'+(view===item.id?' active':'')} {...link(item.id)} aria-label={item.label} aria-current={view===item.id?'page':undefined}><item.icon size={16} aria-hidden="true"/><span>{item.label}</span>{navBadge[item.id]!==undefined&&<span className="nav-badge" aria-hidden="true">{navBadge[item.id]}</span>}</a>)}</div>)}</nav>
      <div className="sidebar-foot">
        <div className="engine"><span className="pulse" aria-hidden="true"/><span><strong>Local engine online</strong><small>Scans and reports stay on this machine</small></span></div>
        <ThemeToggle/>
      </div>
    </aside>
    <div className="main">
      <header className="topbar">
        <nav className="crumbs" aria-label="Breadcrumb"><a {...link('overview')}>ProjectN</a>{scan&&view!=='setup'&&<><ChevronRight size={13} aria-hidden="true"/><a href={routeUrl('overview',scan.id)} onClick={event=>{if(plainClick(event)){event.preventDefault();go('overview')}}}><code>#{shortId(scan.id)}</code></a></>}<ChevronRight size={13} aria-hidden="true"/><span aria-current="page">{titles[view]}</span></nav>
        <div className="top-actions">
          {active&&<a className="live" {...link('overview')}><span className="live-dot" aria-hidden="true"/>Scanning · {percent}%</a>}
          <span className="local"><LockKeyhole size={13} aria-hidden="true"/>Local only</span>
        </div>
      </header>
      <main className="content">
        {error&&<div className="notice error banner" role="alert"><CircleAlert size={16} aria-hidden="true"/><span>{error}</span><button type="button" onClick={()=>setError('')}>Dismiss</button></div>}
        {view==='overview'&&overview}
        {view==='findings'&&findingsView}
        {view==='coverage'&&coverageView}
        {view==='assets'&&assetsView}
        {view==='setup'&&setupView}
      </main>
    </div>
    {selected&&<div className="drawer-backdrop" onClick={closeFinding}>
      <aside className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-title" onClick={e=>e.stopPropagation()}>
        <div className="drawer-head"><div className="drawer-kicker"><SeverityBadge level={selected.severity}/><span className="tag">{scannerLabel(selected.scanner)}</span></div><button ref={closeButton} type="button" className="icon-btn" onClick={closeFinding} aria-label="Close finding (Esc)"><X size={16} aria-hidden="true"/></button></div>
        <h2 id="finding-title">{selected.title}</h2>
        <dl className="facts">
          <Fact icon={MapPin} label="Location"><code>{selected.location||'No location provided'}</code></Fact>
          <Fact icon={FileSearch} label="Evidence">{selected.evidence}</Fact>
          <Fact icon={Gauge} label="Confidence">{selected.confidence}</Fact>
          <Fact icon={Wrench} label="How to fix">{selected.remediation}</Fact>
          <Fact icon={BadgeCheck} label="Verify the fix">{selected.verification}</Fact>
          <Fact icon={Hash} label="Rule"><code>{selected.rule||'—'}</code></Fact>
          {findingHistory&&findingHistory.seen_in_scans>1&&findingHistory.first_seen&&<Fact icon={History} label="First observed">{formatTime(findingHistory.first_seen)} · seen in {findingHistory.seen_in_scans} scans on this target</Fact>}
        </dl>
        {['surface','tls','tls_config','dependencies','performance','journeys','templates','application','accessibility','infra','slopsquat','supabase','firebase','graphql','signup_limits'].includes(selected.scanner)&&<section className="ai-draft">
          <h3><Sparkles size={15} aria-hidden="true"/>Optional AI draft</h3>
          {assistantStatus?.external&&<label className="consent"><input type="checkbox" checked={allowExternal} onChange={e=>setAllowExternal(e.target.checked)}/><span>Send this selected finding to OpenRouter for an AI draft.</span></label>}
          <button type="button" className="btn secondary" disabled={draftBusy||!assistantStatus?.configured||(!!assistantStatus?.external&&!allowExternal)} onClick={()=>requestDraft(selected)}>{draftBusy?<><LoaderCircle size={14} className="spin" aria-hidden="true"/>Working…</>:<><Sparkles size={14} aria-hidden="true"/>Draft with {assistantStatus?.provider||'configured provider'}</>}</button>
          {!assistantStatus?.configured&&<p className="muted">AI is off. The scanner's fix guidance above works without a model or API key.</p>}
          {draftError&&<div className="notice error"><CircleAlert size={15} aria-hidden="true"/>{draftError}</div>}
          {draft&&<div className="draft"><p>{draft.summary}</p><ol>{draft.fix_steps.map((step,index)=><li key={index}>{step}</li>)}</ol><p><strong>Verify:</strong> {draft.verification}</p><p><strong>Uncertainty:</strong> {draft.uncertainty}</p><small>{draft.status} · {draft.model} · {draft.citation}</small></div>}
        </section>}
      </aside>
    </div>}
  </div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
