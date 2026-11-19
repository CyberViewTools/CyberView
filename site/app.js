// CyberView page script. Loaded as a file so the Content Security Policy can forbid inline scripts.
(function(){
"use strict";
var CATS=[
  {k:"incident",label:"Incidents",one:"Incident",sym:d3.symbolCircle},
  {k:"report",label:"Threat reports",one:"Threat report",sym:d3.symbolDiamond},
  {k:"vuln",label:"Patches & advisories",one:"Patch / advisory",sym:d3.symbolTriangle},
  {k:"policy",label:"Law & policy",one:"Law / policy",sym:d3.symbolSquare},
  {k:"enforcement",label:"Law enforcement",one:"Law enforcement",sym:d3.symbolStar},
  {k:"investment",label:"Investment & vendors",one:"Investment / vendor",sym:d3.symbolCross},
  {k:"outage",label:"Outages",one:"Outage",sym:d3.symbolWye}
];
var CAT={};CATS.forEach(function(c){CAT[c.k]=c;});
var STATUS={confirmed:"Confirmed",official:"Official",claimed:"Claimed",developing:"Developing"};
var VAL={corroborated:["Corroborated","v-ok","Two or more independent sources, or a primary source, support the core facts."],
  single_source:["Single source","v-warn","Only one publisher found so far."],
  unconfirmed_claim:["Unconfirmed claim","v-bad","An attacker's claim that the named organization has not confirmed."],
  disputed:["Disputed","v-bad","Sources conflict, or the organization denies it."],
  source_unreachable:["Source unreachable","v-bad","The cited source could not be loaded at the last check."]};
var CONF=["Unchecked","Low","Medium","High"];
var CI=/energy|utilit|power|electric|water|health|hospital|government|election|aviation|transport|telecom|critical|ot-ics|\bics\b|oil|gas|rail|shipping|port\b/i;
var ALIAS={"united states":"united states of america","usa":"united states of america","us":"united states of america","uk":"united kingdom","czech republic":"czechia","dr congo":"dem. rep. congo","democratic republic of the congo":"dem. rep. congo","ivory coast":"côte d'ivoire","bosnia and herzegovina":"bosnia and herz.","dominican republic":"dominican rep.","uae":"united arab emirates"};
var TIER={primary:"Primary source",established:"Established outlet",aggregator:"Aggregator only"};
var PIN={victim:"victim location",hq:"headquarters",agency:"agency",actor:"actor origin",researcher:"researcher",country:"country centre",none:""};
var LENS={
  rall:function(e){return !!e.report;},
  rgov:function(e){return !!e.report&&e.report.ptype==="government";},
  rvendor:function(e){return !!e.report&&e.report.ptype==="vendor";},
  ci:function(e){return CI.test(e.lensHay);},
  energy:function(e){return /energy|utilit|power|electric|water|\boil\b|\bgas\b|nuclear|\bgrid\b|pipeline/.test(e.lensHay);},
  health:function(e){return /health|hospital|medical|pharma|clinic|dental|\bnhs\b/.test(e.lensHay);},
  gov:function(e){return /government|public sector|election|municip|ministry|defen[cs]e|military|federal|\bcouncil\b|\bcity of\b/.test(e.lensHay);},
  finance:function(e){return /financ|bank|insur|payment|fintech|credit|accounting|crypto|invest/.test(e.lensHay);},
  telecom:function(e){return /telecom|telco|\bisp\b|broadband|\bsms\b|wireless|mobile operator/.test(e.lensHay);},
  transport:function(e){return /transport|aviation|airline|airport|\brail|shipping|logistic|maritime|\bports?\b|automotive/.test(e.lensHay);},
  tech:function(e){return /technolog|software|saas|cloud|semiconduct|\bai\b|\bweb\b|\berp\b|network security|it services/.test(e.lensHay);},
  edu:function(e){return /educat|universit|school|college|academ/.test(e.lensHay);},
  smb:function(e){return e.tags.some(function(t){return /ransomware|phishing|fraud/.test(t);})||/retail|professional services/i.test(e.sector);}
};
var LAYERS=[["ot","Industrial control: OT, building and plant systems",/ot-ics|scada|\bplc\b|controller|industrial|refrigerat|siemens|codesys|johnson controls|danfoss|copeland/],
  ["edge","Network edge: VPN, firewall, gateway",/vpn|firewall|gateway|netscaler|forti|sonicwall|check point|ivanti|citrix|palo alto|pan-os|cisco|router|big-ip|\bf5\b|barracuda|juniper|gaia/],
  ["identity","Identity: logins, credentials, single sign-on",/identity|\bsso\b|saml|\bmfa\b|okta|entra|active directory|credential|ldap|oauth|password|stealer/],
  ["email","Email and collaboration",/outlook|exchange|e-?mail|microsoft 365|\bteams\b|sharepoint|zoom|gmail|phishing/],
  ["cloud","Cloud, SaaS and AI",/cloud|\baws\b|azure|saas|kubernetes|container|ai-enabled|\bllm\b|\bai\b|api key/],
  ["app","Apps and supply chain: applications, code libraries, build tools",/supply-chain|\bnpm\b|pypi|github|gitlab|java|\bjdk\b|node\.js|react|rails|wordpress|\bsap\b|confluence|atlassian|package|script|puppet|n8n|\bweb/],
  ["endpoint","Endpoints and OS: computers, phones, browsers",/windows|linux|macos|\bios\b|android|chrome|browser|endpoint|kernel|driver|patch tuesday/],
  ["telecom","Telecom: carriers and core network",/telecom|\bbgp\b|\bdns\b|\bsms\b|carrier|\b5g\b|ss7|\birc/],
  ["org","Policy and other: laws, enforcement, business news",/^$/]];
var SECG=[["energy","Energy and utilities"],["health","Healthcare"],["gov","Government"],["finance","Finance"],["telecom","Telecom"],["transport","Transport"],["edu","Education"],["tech","Technology"],["other","Other sectors"]];
var BUILD={version:"1.33",date:"2026-11-19"};
var viz={lane:"layer",mat:"layer"};
var kev=[],ripples=null;
function own(o,k){return typeof k==="string"&&Object.prototype.hasOwnProperty.call(o,k);}
function lsGet(k){try{return window.localStorage.getItem(k);}catch(x){return null;}}
function lsSet(k,v){try{window.localStorage.setItem(k,v);return true;}catch(x){return false;}}
var wl={terms:[],lower:[],res:[],doc:null,mode:"local",stored:true};
var rep={id:null,text:"",fail:false,busy:false};
var savedT=null,feedTop=0,feedKey="",keyShut=true,feedLimit=30,winTop=0;
var daily=null,hist=null,corrections=[],rubricOpen=false;
var state={win:7,cats:new Set(CATS.map(function(c){return c.k;})),sev:1,lens:"all",level:"standard",claims:false,wlOnly:false,status:"all",sort:"pri",q:"",day:null,sel:null,spot:null,country:null,tab:"feed",view:"map",pattern:null};
var analysis=null;var events=[],sweep=null,loaded=false,unavailable=false,stale=false,db=null,query=null,fresh=new Set();
var $=function(id){return document.getElementById(id);};
var reduced=window.matchMedia&&matchMedia("(prefers-reduced-motion:reduce)").matches;
var NS="http://www.w3.org/2000/svg";

function ymd(d){return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0");}
function daysAgo(n){var d=new Date();d.setHours(12,0,0,0);d.setDate(d.getDate()-n);return d;}
function parseDay(s){var p=s.split("-");return new Date(+p[0],+p[1]-1,+p[2],12);}
// date formatters are built once and reused: creating one per call made long feeds slow
var DTF={day:new Intl.DateTimeFormat(undefined,{month:"short",day:"numeric"}),time:new Intl.DateTimeFormat(undefined,{month:"short",day:"numeric",hour:"numeric",minute:"2-digit"}),
  tz:new Intl.DateTimeFormat(undefined,{month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"}),clock:new Intl.DateTimeFormat(undefined,{hour:"numeric",minute:"2-digit"})},dayMemo={};
function fmtDay(s){return dayMemo[s]||(dayMemo[s]=DTF.day.format(parseDay(s)));}
function fmtTime(iso){var t=Date.parse(iso);return isFinite(t)?DTF.time.format(new Date(t)):"";}
function fmtNum(n){return n>=1e9?(n/1e9).toFixed(1).replace(/\.0$/,"")+"B":n>=1e6?(n/1e6).toFixed(1).replace(/\.0$/,"")+"M":n>=1e4?Math.round(n/1e3)+"K":n.toLocaleString();}
function ago(iso){
  var t=Date.parse(iso);if(!isFinite(t))return "";
  var m=Math.max(0,Math.round((Date.now()-t)/60000));
  if(m<1)return "just now";if(m<60)return m+" min ago";
  var h=Math.round(m/60);if(h<48)return h+" h ago";return Math.round(h/24)+" days ago";
}
function nextSweep(){
  var min=sweep&&typeof sweep.sweep_minute==="number"?sweep.sweep_minute:10,now=new Date().getUTCMinutes();
  var d=(min-now+60)%60;return d===0?"now":"in "+d+" min";
}
function fmtWhen(e,long){
  if(!e.hasTime)return fmtDay(e.date);
  var s=(long?DTF.tz:DTF.time).format(new Date(e.t));
  return s+(e.tb&&e.tb!=="occurred"?" ("+e.tb+")":"");
}
function cleanAnalysis(d){
  if(!d||typeof d!=="object"||!Array.isArray(d.patterns))return null;
  var ids=function(a){return (Array.isArray(a)?a:[]).map(function(x){return str(x,120);}).filter(Boolean).slice(0,60);};
  return {generated:str(d.generated_at,30),summary:str(d.summary,900),patterns:d.patterns.slice(0,24).map(function(p,i){
    if(!p||typeof p!=="object")return null;
    var kind={stated:1,inferred:1,timing:1}[p.kind]?p.kind:"inferred";
    return {id:str(p.id,60)||("p"+i),title:str(p.title,110)||"Pattern",kind:kind,conf:Math.min(3,Math.max(1,Math.round(+p.confidence)||1)),
      narrative:str(p.narrative,900),caveat:str(p.caveat,400),ids:ids(p.event_ids),chain:ids(p.chain),
      edges:(Array.isArray(p.edges)?p.edges:[]).slice(0,80).map(function(x){return x&&typeof x==="object"?{from:str(x.from,120),to:str(x.to,120),rel:str(x.rel,60),basis:{stated:1,inferred:1,timing:1}[x.basis]?x.basis:kind}:null;}).filter(Boolean)};
  }).filter(Boolean)};
}
function curPattern(){return analysis&&state.pattern?analysis.patterns.find(function(p){return p.id===state.pattern;}):null;}
function str(v,max){return typeof v==="string"?v.slice(0,max||400):"";}
function numIn(v,lo,hi){return typeof v==="number"&&isFinite(v)&&v>=lo&&v<=hi?v:null;}
function strs(a,n,len){return (Array.isArray(a)?a:[]).map(function(c){return str(c,len).trim();}).filter(Boolean).slice(0,n);}
function isDay(s){return /^\d{4}-\d{2}-\d{2}$/.test(s)&&isFinite(parseDay(s).getTime());}
/* ---------- watchlist ---------- */
var WL_MAX=150;
function wlParse(s){
  var seen={},out=[];
  String(s||"").slice(0,12000).split(/[,\n]/).forEach(function(t){
    t=t.replace(/[\u0000-\u001f<>]/g,"").replace(/\s+/g," ").trim().slice(0,60);var k=t.toLowerCase();
    if(k.length>=2&&!seen["k"+k]){seen["k"+k]=1;out.push(t);}
  });
  return out.slice(0,WL_MAX);
}
/* whole-word matching, so "SAP" does not match "sapphire" */
function wlRe(t){return new RegExp("(^|[^a-z0-9])"+t.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g,"\\$&")+"($|[^a-z0-9])");}
function wlHit(hay){for(var i=0;i<wl.res.length;i++){if(wl.res[i].test(hay))return true;}return false;}
function wlClean(a){return wlParse((Array.isArray(a)?a:[]).filter(function(x){return typeof x==="string";}).join("\n"));}
function wlTest(e){return wlHit(e.wlHay);}
function wlApply(terms){wl.terms=terms;wl.lower=terms.map(function(t){return t.toLowerCase();});wl.res=terms.map(wlRe);events.forEach(function(e){e.wl=wlTest(e);});}
function cleanRipples(d){
  if(!d||typeof d!=="object"||!Array.isArray(d.items))return null;
  return {generated:str(d.generated_at,30),items:d.items.slice(0,12).map(function(r){if(!r||typeof r!=="object")return null;var id=str(r.event_id,120);if(!id)return null;
    return {id:id,direct:strs(r.direct,4,200),downstream:strs(r.downstream,4,200),watch:strs(r.watch_for,4,200),who:strs(r.who_should_care,4,40),basis:r.basis==="stated"?"stated":"inferred"};}).filter(function(r){return r&&(r.direct.length||r.downstream.length);})};
}
function cleanBrief(d){
  if(!d||typeof d!=="object")return null;
  var b={generated:str(d.generated_at,30),date:str(d.date,10),headline:str(d.headline,200),summary:str(d.plain_summary,1200),
    items:(Array.isArray(d.items)?d.items:[]).slice(0,8).map(function(x){
      if(!x||typeof x!=="object")return null;
      var it={title:str(x.title,200),why:str(x.why,400),action:str(x.action,300),id:str(x.event_id,120)};
      return it.title||it.why?it:null;
    }).filter(Boolean)};
  return b.headline||b.summary||b.items.length?b:null;
}
function cleanHist(d){
  if(!d||typeof d!=="object"||!d.days||typeof d.days!=="object")return null;
  var out=[];
  Object.keys(d.days).forEach(function(k){
    if(!isDay(k))return;var v=d.days[k];if(!v||typeof v!=="object")return;
    var t=numIn(v.total,0,1e6);
    if(t===null){t=0;CATS.forEach(function(c){t+=numIn(v[c.k],0,1e6)||0;});}
    out.push({d:k,n:Math.round(t)});
  });
  out.sort(function(a,b){return a.d<b.d?-1:1;});
  return out.slice(-28);
}
function cleanCorr(d){
  if(!d||typeof d!=="object")return null;
  var c={at:str(d.at,30),id:str(d.event_id,120),title:str(d.title,200),what:str(d.what_changed,400)};
  return c.title||c.what?c:null;
}
/* ---------- context layers: not cyber events; fetched at build time by scripts/context.mjs ---------- */
var CTX_DEFS={
  ioda:{label:"Internet disruptions",what:"Countries where IODA's automated measurements (routing, active probing, Google traffic) saw a drop in the last 24 hours. A signal, not a confirmed outage, and never by itself evidence of an attack.",host:/^https:\/\/ioda\.inetintel\.cc\.gatech\.edu\//},
  gdacs:{label:"Disaster alerts",what:"Orange and red GDACS alerts now in effect (earthquakes, cyclones, floods, volcanoes). Disasters cause outages and draw scams; they are context, not cyber events.",host:/^https:\/\/www\.gdacs\.org\//}
};
var ctx={},ctxOn={ioda:false,gdacs:true};
function cleanCtx(name,d){
  var def=CTX_DEFS[name];if(!def||!d||typeof d!=="object"||!Array.isArray(d.items))return null;
  var link=function(u){u=str(u,300);return def.host.test(u)?u:"";};
  var items=d.items.slice(0,60).map(function(x){
    if(!x||typeof x!=="object")return null;
    if(name==="ioda"){var code=str(x.code,2);if(!/^[A-Z]{2}$/.test(code))return null;
      return {code:code,name:str(x.name,60),map:str(x.map_name,60).toLowerCase(),score:numIn(x.score,0,1e9)||0,events:numIn(x.events,0,1e4)||0,signals:strs(x.signals,4,20),url:link(x.url)};}
    var lat=numIn(x.lat,-90,90),lng=numIn(x.lng,-180,180);if(lat===null||lng===null)return null;
    return {id:str(x.id,40),type:str(x.type,30),level:x.level==="red"?"red":"orange",name:str(x.name,120),country:str(x.country,80),from:str(x.from,19),lat:lat,lng:lng,url:link(x.url)};
  }).filter(Boolean);
  var at=str(d.fetched_at,30);
  return {source:str(d.source,100),url:link(d.source_url),at:at,ok:d.ok===true,error:str(d.error,60),items:items};
}
function ctxHealth(c){
  if(!c)return {k:"off",t:"Offline"};
  var h=(Date.now()-Date.parse(c.at))/36e5,age=isFinite(h)?ago(c.at):"";
  if(!c.ok)return c.items.length?{k:"stale",t:"Stale"+(age?" · "+age:"")}:{k:"off",t:"Offline"};
  return h<=5?{k:"live",t:"Live · "+age}:{k:"stale",t:"Stale · "+age};
}
function renderLayers(){
  var box=$("layers");if(!box||box.hidden)return;box.textContent="";
  box.appendChild(el("h3",null,"Map layers"));
  var ev=el("div","lrow");ev.appendChild(el("span","lname","Cyber events"));ev.appendChild(el("span","lh h-live","Always on"));box.appendChild(ev);
  var arcs=arcsFor(lastList);
  Object.keys(ARC_DEFS).forEach(function(k){
    var def=ARC_DEFS[k],r=el("div","lrow"),n=arcs.filter(function(x){return x.kind===(k==="links"?"link":"origin");}).length;
    var b=el("button","chip tog",def.label+" ");b.type="button";b.setAttribute("aria-pressed",arcOn[k]?"true":"false");b.title=def.what;b.dataset.arc=k;
    b.appendChild(el("span","n",arcOn[k]?String(n):"off"));
    b.addEventListener("click",function(){arcOn[k]=!arcOn[k];lsSet("cwm.arcs",JSON.stringify(arcOn));render();renderLayers();});
    r.appendChild(b);r.appendChild(el("span","lh h-live",arcOn[k]?(n?n+" on screen":"none on screen"):"Hidden"));box.appendChild(r);
    box.appendChild(el("p","lnote",def.what));
  });
  Object.keys(CTX_DEFS).forEach(function(k){
    var def=CTX_DEFS[k],c=ctx[k],h=ctxHealth(c),r=el("div","lrow");
    var b=el("button","chip tog",def.label+" ");b.type="button";b.setAttribute("aria-pressed",ctxOn[k]?"true":"false");b.title=def.what;
    b.appendChild(el("span","n",c?String(c.items.length):"0"));
    b.addEventListener("click",function(){ctxOn[k]=!ctxOn[k];render();renderLayers();});
    r.appendChild(b);r.appendChild(el("span","lh h-"+h.k,h.t));box.appendChild(r);
    box.appendChild(el("p","lnote",def.what));
    if(c&&c.items.length&&ctxOn[k]){
      var ul=el("ul","llist");
      c.items.slice(0,k==="ioda"?6:5).forEach(function(x){
        var li=el("li"),a=el("a",null,k==="ioda"?x.name:x.name);a.href=safeUrl(x.url);a.target="_blank";a.rel="noopener noreferrer";li.appendChild(a);
        li.appendChild(el("span","muted",k==="ioda"?" "+x.signals.join(", ")+(x.map?"":" · not drawn (too small for this map)"):" "+x.level+" alert"+(x.country?" · "+x.country:"")));
        ul.appendChild(li);});
      box.appendChild(ul);
    }
    if(c){var src=el("p","lsrc","Source: ");var sa=el("a",null,c.source);sa.href=safeUrl(c.url);sa.target="_blank";sa.rel="noopener noreferrer";src.appendChild(sa);if(c.error)src.appendChild(document.createTextNode(" · last fetch failed ("+c.error+")"));box.appendChild(src);}
  });
}
function layersToggle(open){var b=$("layers");b.hidden=!open;$("zlayers").setAttribute("aria-expanded",open?"true":"false");if(open)renderLayers();}

/* ---------- HUD clock and intel wire ---------- */
var wireI=0,wireItems=[],builtAt="",loadFailing=0;
/* Data freshness, said plainly: the pipeline rebuilds the data at least every 30 minutes, so data older than 3 hours means
   something upstream has stopped; a failing reload means this browser cannot reach the site and is showing a stored copy. */
function freshness(){
  var h=(Date.now()-Date.parse(builtAt))/36e5;if(!builtAt||!isFinite(h))return "";
  if(loadFailing>=2)return "CyberView can't be reached right now. You are seeing the copy from "+ago(builtAt)+"; it will update by itself when the connection returns.";
  if(h>=3)return "This data was last updated "+ago(builtAt)+". New data is not arriving, which is a fault on CyberView's side, not yours. Check primary sources for anything urgent.";
  return "";
}
function hudTick(){var h=$("hud");if(!h)return;var d=new Date();h.textContent="UTC "+pad2(d.getUTCHours())+":"+pad2(d.getUTCMinutes());h.title="Coordinated Universal Time. Data built "+(builtAt?ago(builtAt):"(not loaded yet)")+".";}
function pad2(n){return (n<10?"0":"")+n;}
var wireKey="";
function wireBuild(){
  var key=events.length+"|"+(kev||[]).length+"|"+builtAt+"|"+state.claims;if(key===wireKey)return;wireKey=key;
  var cut=Date.now()-36*3600e3;
  var a=events.filter(function(e){return (state.claims||e.status!=="claimed")&&Date.parse(e.firstSeen)>cut;})
    .sort(function(x,y){return Date.parse(y.firstSeen)-Date.parse(x.firstSeen);}).slice(0,6)
    .map(function(e){return {t:e.title,when:e.firstSeen,go:function(){select(e.id,true);}};});
  (kev||[]).filter(function(k){return k&&k.added>=ymd(daysAgo(1));}).slice(0,3).forEach(function(k){
    a.push({t:"Known exploited: "+k.cve+(k.vendor?" ("+k.vendor+" "+k.product+")":""),when:k.added,go:function(){location.href="vulnerabilities.html#"+encodeURIComponent(k.cve);}});});
  wireItems=a;wireShow();
}
function wireShow(){
  var w=$("wire");if(!w)return;w.textContent="";
  if(!wireItems.length){w.hidden=true;return;}w.hidden=false;
  var it=wireItems[wireI%wireItems.length];
  w.appendChild(el("span","wtag","Wire"));
  var b=el("button","wtxt",it.t);b.type="button";b.title="Newest first. Open this item";b.addEventListener("click",it.go);w.appendChild(b);
  w.appendChild(el("span","wwhen",ago(it.when)||""));
}
setInterval(function(){hudTick();if(!reduced&&!document.hidden&&wireItems.length>1){wireI++;wireShow();}},8000);

function normC(s){s=(s||"").toLowerCase().trim();return ALIAS[s]||s;}
function clean(id,d){
  if(!d||typeof d!=="object")return null;
  if(typeof d.duplicate_of==="string"&&d.duplicate_of&&d.duplicate_of!==id)return null; /* flagged by the data-quality pass; the richer record is shown */
  var date=str(d.date,10);if(!/^\d{4}-\d{2}-\d{2}$/.test(date))return null;
  var lat=typeof d.lat==="number"&&isFinite(d.lat)&&Math.abs(d.lat)<=90?d.lat:null;
  var lng=typeof d.lng==="number"&&isFinite(d.lng)&&Math.abs(d.lng)<=180?d.lng:null;
  if(lat===null||lng===null){lat=null;lng=null;}
  var sources=(Array.isArray(d.sources)?d.sources:[]).map(function(s){
    var u=str(s&&s.url,600);return /^https?:\/\//i.test(u)?{name:str(s.name,80)||u.replace(/^https?:\/\//,"").split("/")[0],url:u}:null;
  }).filter(Boolean).slice(0,6);
  var v=d.validation&&typeof d.validation==="object"&&VAL[d.validation.state]?{state:d.validation.state,checked:str(d.validation.checked_at,30),note:str(d.validation.note,240)}:null;
  var e={id:id,title:str(d.title,200)||"Untitled event",date:date,dateNote:str(d.date_note,160),
    category:CAT[d.category]?d.category:"report",severity:Math.min(3,Math.max(1,Math.round(+d.severity)||1)),
    status:STATUS[d.status]?d.status:"developing",org:str(d.org,120),sector:str(d.sector,80),country:str(d.country,60),
    place:str(d.place,80),lat:lat,lng:lng,geo:str(d.geo_basis,40),actor:str(d.actor,120),summary:str(d.summary,900),impact:str(d.impact,600),
    cves:(Array.isArray(d.cves)?d.cves:[]).map(function(c){return str(c,24);}).filter(Boolean).slice(0,8),
    tags:(Array.isArray(d.tags)?d.tags:[]).map(function(c){return str(c,28).toLowerCase();}).filter(Boolean).slice(0,6),
    records:typeof d.records_affected==="number"&&isFinite(d.records_affected)&&d.records_affected>0?Math.round(d.records_affected):0,
    sources:sources,val:v,firstSeen:str(d.first_seen,30),updated:str(d.updated_at,30),tb:str(d.time_basis,20)};
  var ot=Date.parse(str(d.occurred_at,40));e.hasTime=isFinite(ot);e.t=e.hasTime?ot:parseDay(date).getTime();
  var ok=e.status==="confirmed"||e.status==="official";
  e.conf=!v?(e.status==="claimed"?1:0):v.state==="corroborated"?(ok?3:e.status==="developing"?2:1):v.state==="single_source"?(e.status==="claimed"?1:2):1;
  e.ci=CI.test(e.sector+" "+e.tags.join(" "));
  e.isNew=isFinite(Date.parse(e.firstSeen))&&Date.now()-Date.parse(e.firstSeen)<3*3600e3;
  e.action=str(d.action,300);e.plain=str(d.plain,260);e.exec=str(d.exec,180);
  e.tier=own(TIER,d.source_tier)?d.source_tier:"";e.pin=own(PIN,d.pin_type)?d.pin_type:"";
  e.products=strs(d.products,8,60);e.attack=strs(d.attack,4,80);
  var rp=d.report;e.report=null;
  if(rp&&typeof rp==="object"&&str(rp.publisher,80)){var ru=str(rp.url,600);
    e.report={publisher:str(rp.publisher,80),ptype:rp.publisher_type==="government"?"government":"vendor",docId:str(rp.doc_id,60),published:str(rp.published,30),
      findings:strs(rp.key_findings,6,260),recs:strs(rp.recommendations,6,260),iocs:rp.iocs_available===true,read:str(rp.read_depth,20),url:/^https?:\/\//i.test(ru)?ru:""};}
  e.cveMeta=(Array.isArray(d.cve_meta)?d.cve_meta:[]).map(function(c){
    if(!c||typeof c!=="object")return null;var cid=str(c.id,24);if(!cid)return null;
    var due=str(c.kev_due,10);
    return {id:cid,cvss:numIn(c.cvss,0,10),epss:numIn(c.epss,0,1),kev:c.kev===true,due:isDay(due)?due:""};
  }).filter(Boolean).slice(0,8);
  e.kev=e.cveMeta.some(function(c){return c.kev;})?1:0;
  e.epss=e.cveMeta.reduce(function(m,c){return c.epss!==null&&c.epss>m?c.epss:m;},-1);
  e.cvss=e.cveMeta.reduce(function(m,c){return c.cvss!==null&&c.cvss>m?c.cvss:m;},-1);
  /* attribution only when a government or the investigating firm made it, with the page that says so */
  var at=d.attribution;e.attr=null;
  if(at&&typeof at==="object"&&(at.by_type==="government"||at.by_type==="investigator")){var aLat=numIn(at.lat,-90,90),aLng=numIn(at.lng,-180,180),au=str(at.url,600);
    if(aLat!==null&&aLng!==null&&/^https:\/\//i.test(au)&&str(at.by,120)&&str(at.actor,120))e.attr={actor:str(at.actor,120),origin:str(at.origin_country,60),lat:aLat,lng:aLng,by:str(at.by,120),byType:at.by_type,url:au};}
  e.links=(Array.isArray(d.links)?d.links:[]).slice(0,40).map(function(l){if(!l||typeof l!=="object")return null;var to=str(l.to,120),u=str(l.url,600);
    return /^[a-z0-9][a-z0-9-]{2,119}$/.test(to)&&to!==id&&/^https:\/\//i.test(u)?{to:to,rel:str(l.rel,60)||"linked",url:u}:null;}).filter(Boolean);
  var rv=d.review;e.review=rv&&typeof rv==="object"&&{passed:1,corrected:1,flagged:1}[rv.state]&&str(rv.at,30)?{state:rv.state,at:str(rv.at,30),note:str(rv.note,300)}:null;
  var HF={stix:"STIX",sigma:"Sigma rule",yara:"YARA rule",snort:"Snort rule",suricata:"Suricata rule",kql:"KQL query",spl:"Splunk query",csv:"CSV indicators",json:"JSON indicators",misp:"MISP event",openioc:"OpenIOC",text:"Indicator list",pdf:"PDF with indicators"};
  e.hunt=(Array.isArray(d.hunt)?d.hunt:[]).slice(0,12).map(function(h){if(!h||typeof h!=="object"||!own(HF,h.format))return null;var hu=str(h.url,600);
    return /^https:\/\//i.test(hu)?{name:str(h.name,100)||HF[h.format],fmt:HF[h.format],url:hu}:null;}).filter(Boolean);
  e.actorPin=e.pin==="actor"||/actor origin/i.test(e.geo);e.countryPin=!e.actorPin&&e.pin==="country";
  e.wlHay=[e.title,e.org,e.sector,e.country,e.products.join(" | "),e.tags.join(" | "),e.actor,e.cves.join(" ")].join(" | ").toLowerCase();
  e.lensHay=(e.sector+" "+e.tags.join(" ")+" "+e.org).toLowerCase();
  var lh=(e.title+" "+e.products.join(" ")+" "+e.tags.join(" ")+" "+e.sector).toLowerCase();
  e.layer="org";
  if(e.category==="incident"||e.category==="vuln"||e.category==="report"||e.category==="outage"){for(var li=0;li<LAYERS.length;li++){if(LAYERS[li][2].test(lh)){e.layer=LAYERS[li][0];break;}}}
  e.secg="other";for(var si=0;si<SECG.length;si++){if(own(LENS,SECG[si][0])&&LENS[SECG[si][0]](e)){e.secg=SECG[si][0];break;}}
  e.wl=wlTest(e);
  return e;
}
function symPath(cat,size){return d3.symbol().type(CAT[cat].sym).size(size)();}
function glyph(cat,hollow){
  var s=document.createElementNS(NS,"svg");s.setAttribute("viewBox","-8 -8 16 16");s.setAttribute("aria-hidden","true");
  var p=document.createElementNS(NS,"path");p.setAttribute("d",symPath(cat,110));
  if(hollow){p.setAttribute("fill","none");p.setAttribute("stroke","var(--c-"+cat+")");p.setAttribute("stroke-width","2");}
  else p.setAttribute("fill","var(--c-"+cat+")");
  s.appendChild(p);return s;
}
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e;}
function confEl(e){var c=el("span","conf c"+e.conf);c.title="Confidence: "+CONF[e.conf];for(var i=0;i<3;i++)c.appendChild(el("i"));c.appendChild(document.createTextNode(CONF[e.conf]));return c;}
var toastT=0;
function toast(msg){var t=$("toast");t.textContent=msg;t.hidden=false;clearTimeout(toastT);toastT=setTimeout(function(){t.hidden=true;},4200);}

/* ---------- filtering ---------- */
function priOf(e){
  var s=e.severity*20;
  if(e.wl)s+=60;if(e.kev)s+=35;if(e.tags.indexOf("zero-day")>=0)s+=15;if(e.epss>=.5)s+=10;
  if(e.status==="claimed")s-=30;else if(e.conf>=3)s+=6;
  if(e.action)s+=5;if(e.category==="incident"||e.category==="vuln")s+=8;if(e.category==="outage")s+=4;
  var age=isFinite(e.t)?(Date.now()-e.t)/864e5:7;
  return s-Math.min(7,Math.max(0,age))*4;
}
function urgent(e){return e.status!=="claimed"&&(e.kev||e.wl||e.severity>=3||(e.severity>=2&&(e.category==="vuln"||e.category==="incident")));}
function nav(d){
  var list=lastList;if(!list.length)return;
  var i=list.findIndex(function(e){return e.id===state.sel;});
  var n=i<0?(d>0?0:list.length-1):i+d;
  if(n<0||n>=list.length)return;
  select(list[n].id,true);
}
/* "N days" is today and the N-1 calendar days before it, on the map, the day bars, the counts and the handover alike */
function inWindow(e){return e.date>=ymd(daysAgo(state.win-1))&&e.date<=ymd(daysAgo(-1));}
function matchQ(e){
  if(!state.q)return true;
  var hay=[e.title,e.org,e.country,e.place,e.sector,e.actor,e.summary,e.cves.join(" "),e.tags.join(" ")].join(" ").toLowerCase();
  return state.q.toLowerCase().split(/\s+/).every(function(w){return hay.indexOf(w)>=0;});
}
function matchStatus(e){
  if(state.status==="all")return true;
  if(state.status==="corroborated")return !!e.val&&e.val.state==="corroborated";
  var open=e.status==="claimed"||e.status==="developing";
  return state.status==="open"?open:!open;
}
function claimOk(e){return state.claims||e.status!=="claimed";}
function lensOk(e){return state.lens==="all"||!own(LENS,state.lens)||LENS[state.lens](e);}
function base(all){var only=state.wlOnly&&wl.terms.length>0;return events.filter(function(e){return inWindow(e)&&matchQ(e)&&matchStatus(e)&&e.severity>=state.sev&&lensOk(e)&&(!only||e.wl)&&(all||claimOk(e));});}
function scoped(){return base().filter(function(e){return state.cats.has(e.category)&&(!state.country||normC(e.country)===state.country);});}
function visible(){
  var cmp={new:function(a,b){return a.date<b.date?1:a.date>b.date?-1:(b.t-a.t)||b.severity-a.severity;},
    sev:function(a,b){return b.severity-a.severity||(a.date<b.date?1:-1);},
    upd:function(a,b){return (b.updated||"").localeCompare(a.updated||"")||(a.date<b.date?1:-1);},
    rec:function(a,b){return b.records-a.records||b.severity-a.severity;},
    pri:function(a,b){return b.pri-a.pri||(a.date<b.date?1:-1);},
    risk:function(a,b){return (b.kev-a.kev)||(b.epss-a.epss)||(b.cvss-a.cvss)||b.severity-a.severity||(a.date<b.date?1:-1);}}[state.sort];
  var cp=curPattern();
  return scoped().filter(function(e){e.pri=priOf(e);return (!state.day||e.date===state.day)&&(!state.spot||state.spot.indexOf(e.id)>=0)&&(!cp||cp.ids.indexOf(e.id)>=0);})
    .sort(function(a,b){return (state.sort==="pri"?0:((b.wl?1:0)-(a.wl?1:0)))||cmp(a,b);});
}

/* ---------- header ---------- */
function renderStats(list){
  var s=$("stats");s.textContent="";
  $("live").className="live"+(unavailable||stale||freshness()?" off":"");
  if(!loaded){s.textContent=unavailable?"Live data unavailable":"Loading events";return;}
  var mapped=list.filter(function(e){return e.lat!==null;}).length;
  s.appendChild(el("b",null,String(list.length)));s.appendChild(document.createTextNode(" events · "));
  var todo=list.filter(function(e){return urgent(e);}).length;
  s.appendChild(el("b",null,String(todo)));s.appendChild(document.createTextNode(" high priority · "));
  s.appendChild(el("b",null,String(mapped)));s.appendChild(document.createTextNode(" on map"));s.title="As of "+new Date().toLocaleTimeString(undefined,{hour:"numeric",minute:"2-digit",timeZoneName:"short"});
  var a=sweep&&ago(sweep.last_sweep_at);
  if(a){s.appendChild(document.createTextNode(" · swept "));s.appendChild(el("b",null,a));s.appendChild(document.createTextNode(" · next "+nextSweep()));}
  var ws=$("wlStat");ws.textContent="";
  if(wl.terms.length){ws.appendChild(el("b","wlstat",String(list.filter(function(e){return e.wl;}).length)));ws.appendChild(document.createTextNode(" match your environment"));}
}
function renderToggles(){
  var n=base(true).filter(function(e){return e.status==="claimed";}).length;
  $("claims").setAttribute("aria-pressed",state.claims?"true":"false");
  $("claimsN").textContent=n+(state.claims?" shown":" hidden");
  var has=wl.terms.length>0;
  $("wlOnly").disabled=!has;$("wlOnly").setAttribute("aria-pressed",state.wlOnly&&has?"true":"false");
  $("wlOpen").textContent=has?"My environment ("+wl.terms.length+")":"My environment";

}
function renderChips(){
  var b=base().filter(function(e){return (!state.day||e.date===state.day)&&(!state.country||normC(e.country)===state.country);});
  var box=$("chips");box.textContent="";
  CATS.forEach(function(c){
    var n=b.filter(function(e){return e.category===c.k;}).length;
    var btn=el("button","chip");btn.type="button";btn.setAttribute("aria-pressed",state.cats.has(c.k)?"true":"false");
    btn.appendChild(glyph(c.k));btn.appendChild(el("span",null,c.label));btn.appendChild(el("span","n",String(n)));
    btn.addEventListener("click",function(ev){
      if(ev.shiftKey||ev.altKey){state.cats=new Set([c.k]);}
      else if(state.cats.has(c.k))state.cats.delete(c.k);else state.cats.add(c.k);
      if(state.cats.size===0)state.cats=new Set(CATS.map(function(x){return x.k;}));
      render();
    });
    btn.title="Click to toggle. Shift-click to show only this type.";
    box.appendChild(btn);
  });
}
/* ---------- time-lapse: step the day filter through the window so the map shows how the week unfolded ---------- */
var play={timer:null,days:[],i:0};
function playing(){return !!play.timer;}
function stopPlay(keepDay){if(play.timer)clearInterval(play.timer);play.timer=null;if(!keepDay)state.day=null;render();}
function startPlay(days){
  if(play.timer)clearInterval(play.timer);
  play.days=days.slice();play.i=0;state.sel=null;state.day=play.days[0];render();
  var step=window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches?2600:1400;
  play.timer=setInterval(function(){
    if(state.day!==play.days[play.i]){if(play.timer)clearInterval(play.timer);play.timer=null;render();return;}   // the visitor took over
    play.i++;
    if(play.i>=play.days.length){stopPlay(false);toast("End of the window. Press play to watch it again.");return;}
    state.day=play.days[play.i];render();
  },step);
}
function renderDays(){
  var b=scoped();
  var days=winDays();
  var counts=days.map(function(d){return b.filter(function(e){return e.date===d;}).length;});
  var max=Math.max(1,d3.max(counts));
  var box=$("days");box.textContent="";
  var pb=el("button","day play");pb.type="button";pb.id="playDays";
  pb.setAttribute("aria-label",playing()?"Pause the time-lapse":"Play the window day by day");pb.title=pb.getAttribute("aria-label");
  pb.setAttribute("aria-pressed",playing()?"true":"false");
  var ns="http://www.w3.org/2000/svg",ic=document.createElementNS(ns,"svg");ic.setAttribute("viewBox","0 0 24 24");ic.setAttribute("aria-hidden","true");
  var path=document.createElementNS(ns,"path");path.setAttribute("d",playing()?"M7 5h3.5v14H7zM13.5 5H17v14h-3.5z":"M8 5.5v13l10.5-6.5z");path.setAttribute("fill","currentColor");ic.appendChild(path);
  pb.appendChild(ic);pb.appendChild(el("span","lab",playing()?"Pause":"Play"));
  pb.addEventListener("click",function(){if(playing())stopPlay(true);else startPlay(days);});
  box.appendChild(pb);
  days.forEach(function(d,i){
    var btn=el("button","day"+(state.day&&state.day!==d?" dim":""));btn.type="button";
    btn.setAttribute("aria-pressed",state.day===d?"true":"false");
    btn.setAttribute("aria-label",counts[i]+" events on "+fmtDay(d));
    btn.appendChild(el("span","cnt",String(counts[i])));
    var bar=el("span","bar");bar.style.height=Math.round(counts[i]/max*34)+"px";btn.appendChild(bar);
    btn.appendChild(el("span","lab",i===days.length-1?"Today":parseDay(d).toLocaleDateString(undefined,{weekday:"short",day:"numeric"})));
    btn.addEventListener("click",function(){if(play.timer){clearInterval(play.timer);play.timer=null;}state.day=state.day===d?null:d;render();});
    box.appendChild(btn);
  });
}

/* ---------- feed ---------- */
function related(e){
  return events.filter(function(o){
    if(o.id===e.id)return false;
    if(!claimOk(o))return false;
    if(e.org&&o.org===e.org)return true;
    if(e.actor&&o.actor&&o.actor===e.actor)return true;
    return e.cves.some(function(c){return o.cves.indexOf(c)>=0;});
  }).slice(0,4);
}
function brief(e){
  return [e.title,fmtDay(e.date)+" | "+CAT[e.category].one+" | "+[e.place,e.country].filter(Boolean).join(", "),e.summary,
    "Status: "+STATUS[e.status]+" | Confidence: "+CONF[e.conf]+(e.val?" ("+VAL[e.val.state][0]+")":""),
    e.sources.map(function(s){return s.url;}).join("\n")].filter(Boolean).join("\n");
}
function card(e,open){
  var li=el(open?"div":"li");var a=el("article","card s"+e.severity+(state.sel===e.id?" sel":"")+(fresh.has(e.id)?" fresh":""));a.style.setProperty("--cc","var(--c-"+e.category+")");
  a.id=open?"dcard":"card-"+e.id;open=!!open;
  var h=el("button","head");h.type="button";h.setAttribute("aria-expanded",open?"true":"false");
  h.appendChild(glyph(e.category,e.status==="claimed"));
  var meta=el("span","meta");meta.appendChild(el("span","cat",CAT[e.category].one));meta.appendChild(el("span",null,fmtWhen(e)));
  meta.appendChild(confEl(e));
  if(e.tier)meta.appendChild(el("span","tier "+e.tier,TIER[e.tier]));
  h.appendChild(meta);h.appendChild(el("span","ttl",e.title));
  var sub=el("span","sub");
  var where=[e.place,e.country].filter(function(x,i,arr){return x&&arr.indexOf(x)===i;}).join(", ");
  if(where)sub.appendChild(el("span",null,where));
  if(e.wl)sub.appendChild(el("span","pill wl","Matches your environment"));
  if(e.records)sub.appendChild(el("span","pill mute",fmtNum(e.records)+" records"));
  if(e.isNew)sub.appendChild(el("span","pill new","New"));
  if(e.status==="claimed"||e.status==="developing")sub.appendChild(el("span","pill warn",STATUS[e.status]));
  if(e.kev)sub.appendChild(el("span","pill kev","Known exploited"));
  if(e.report&&e.report.read!=="secondary"&&e.report.read)sub.appendChild(el("span","pill rep",e.report.ptype==="government"?"Gov report":"Vendor report"));
  if(e.lat===null)sub.appendChild(el("span","pill mute","Not on map"));
  h.appendChild(sub);
  if(!open&&e.action&&urgent(e)){var dn=el("span","do");dn.appendChild(el("b",null,"Do: "));dn.appendChild(document.createTextNode(e.action));h.appendChild(dn);}
  if(open)h.tabIndex=-1;
  h.addEventListener("click",function(){if(!open)select(e.id,true);});
  a.appendChild(h);
  if(open){
    var b=el("div","body");
    var tr=el("div","tri");
    function tb(label,key,cls,fn){var x=el("button",cls||null,label);x.type="button";var k=el("kbd",null,key);x.appendChild(k);x.addEventListener("click",fn);tr.appendChild(x);}
    if(e.sources.length){var os=el("button",null,"Open source");os.type="button";os.appendChild(el("kbd",null,"O"));os.addEventListener("click",function(){openSource(e);});tr.appendChild(os);}
    if(tr.childNodes.length)b.appendChild(tr);
    b.appendChild(el("p",null,(state.level==="plain"?e.plain:state.level==="exec"?e.exec:"")||e.summary||"No summary yet."));
    if(e.impact)b.appendChild(el("p",null,"Impact: "+e.impact));
    if(e.action||e.cveMeta.length){
      var td=el("div","todo");td.appendChild(el("h4",null,e.action?"What to do":"Exploit risk"));
      if(e.action)td.appendChild(el("p",null,e.action));
      if(e.cveMeta.length){
        var ct=el("div","cvet");["CVE","CVSS","EPSS","Exploited"].forEach(function(x){ct.appendChild(el("span","h",x));});
        e.cveMeta.forEach(function(c){
          ct.appendChild(el("span",null,c.id));
          ct.appendChild(el("span",null,c.cvss===null?"n/a":c.cvss.toFixed(1)));
          var ep=el("span",null,c.epss===null?"n/a":(c.epss*100>=10?Math.round(c.epss*100):(c.epss*100).toFixed(1))+"%");
          ep.title="EPSS: estimated chance of exploitation in the next 30 days";ct.appendChild(ep);
          var kc=el("span","k");
          if(c.kev){kc.appendChild(el("span","pill kev","Known exploited"));if(c.due)kc.appendChild(el("span",null,"due "+fmtDay(c.due)));}
          else kc.appendChild(el("span",null,"not listed"));
          ct.appendChild(kc);
        });
        td.appendChild(ct);
      }
      b.appendChild(td);
    }
    if(e.report){
      var rv=el("div","todo rep"),r=e.report;
      rv.appendChild(el("h4",null,(r.ptype==="government"?"Government report review":"Vendor report review")));
      rv.appendChild(el("p","mono",[r.publisher,r.docId,r.published?(isDay(r.published.slice(0,10))?fmtDay(r.published.slice(0,10)):""):""].filter(Boolean).join(" · ")));
      if(r.findings.length){rv.appendChild(el("p",null,"Key findings"));var fl=el("ul");r.findings.forEach(function(x){fl.appendChild(el("li",null,x));});rv.appendChild(fl);}
      if(r.recs.length){rv.appendChild(el("p",null,"What the report recommends"));var rl=el("ul");r.recs.forEach(function(x){rl.appendChild(el("li",null,x));});rv.appendChild(rl);}
      var foot=el("p","mono",(r.iocs?"Indicators of compromise are published in the report. ":"")+(r.read==="full"?"Reviewed from the full document.":r.read==="summary"?"Reviewed from the publisher's summary page.":r.read?"Reviewed from secondary coverage; the original was not read.":""));
      if(foot.textContent)rv.appendChild(foot);
      if(r.url){var ra=el("a",null,"Open the report");ra.href=safeUrl(r.url);ra.target="_blank";ra.rel="noopener noreferrer";rv.appendChild(ra);}
      b.appendChild(rv);
    }
    var vv=e.val?VAL[e.val.state]:["Not yet checked","v-warn","The validation pass has not reached this event yet."];
    var vb=el("div","val "+vv[1]);vb.appendChild(el("b",null,vv[0]));vb.appendChild(document.createTextNode(" · confidence "+CONF[e.conf].toLowerCase()));
    vb.appendChild(el("small",null,(e.val&&e.val.note)||vv[2]));
    if(e.val&&e.val.checked)vb.appendChild(el("small",null,"Checked "+fmtTime(e.val.checked)));
    if(e.review)vb.appendChild(el("small","rev "+e.review.state,({passed:"Second review: a different agent re-read the sources and found nothing wrong",corrected:"Second review: a different agent re-read the sources and corrected this record",flagged:"Second review: a problem was found and is being settled"})[e.review.state]+" · "+fmtTime(e.review.at)+(e.review.state!=="passed"&&e.review.note?" · "+e.review.note:"")));
    else vb.appendChild(el("small","rev none","Second review: not yet done"));
    b.appendChild(vb);
    if(e.tags.length){var tg=el("div","tags");e.tags.forEach(function(t){tg.appendChild(el("span","tag",t));});b.appendChild(tg);}
    var dl=el("dl");
    function row(k,v,cls){if(!v)return;dl.appendChild(el("dt",null,k));dl.appendChild(el("dd",cls||null,v));}
    row("When",fmtWhen(e,true)+(e.hasTime?"":" (time of day not reported)"),"mono");row("Organization",e.org);row("Sector",e.sector);row("Products",e.products.join(", "));row("Actor",e.actor);row("Techniques",e.attack.join("; "));row("Status",STATUS[e.status]);row("Source quality",e.tier?TIER[e.tier]:"");
    row("Severity",["","Low","Medium","High"][e.severity]);row("Records",e.records?e.records.toLocaleString():"");
    row("CVEs",e.cves.join(", "),"mono");row("Pin shows",[e.geo||(e.pin?PIN[e.pin]:""),e.actorPin?"attributed origin, not a victim location":e.countryPin?"country-level location":""].filter(Boolean).join(" · "));row("Date note",e.dateNote);
    row("First seen",fmtTime(e.firstSeen),"mono");row("Updated",e.updated&&e.updated!==e.firstSeen?fmtTime(e.updated):"","mono");
    if(dl.childNodes.length)b.appendChild(dl);
    if(e.sources.length){
      var s=el("div","srcs");s.appendChild(el("span",null,"Sources ("+e.sources.length+"):"));
      e.sources.forEach(function(x){var l=el("a",null,x.name);l.href=safeUrl(x.url);l.target="_blank";l.rel="noopener noreferrer";s.appendChild(l);});
      b.appendChild(s);
    }
    var acts=el("div","acts");
    var cp=el("button",null,"Copy brief");cp.type="button";cp.addEventListener("click",function(){
      try{navigator.clipboard.writeText(brief(e)).then(function(){toast("Brief copied.");},function(){toast("Copy was blocked by the browser.");});}catch(x){toast("Copy was blocked by the browser.");}
    });acts.appendChild(cp);
    var lk=el("button",null,"Copy link");lk.type="button";lk.title="A link that opens this event";lk.addEventListener("click",function(){
      var u=eventLink(e.id);
      try{navigator.clipboard.writeText(u).then(function(){toast("Link copied.");},function(){toast(u);});}catch(x){toast(u);}
    });acts.appendChild(lk);
    var dc=el("a","abtn","Discuss");dc.href="community.html#e="+encodeURIComponent(e.id);dc.title="Community posts about this event, and a place to add yours (reviewed before they appear)";acts.appendChild(dc);
    if(e.country){var cf=el("button",null,"More from "+e.country);cf.type="button";cf.addEventListener("click",function(){state.country=normC(e.country);select(null);});acts.appendChild(cf);}
    var rpb=el("button",null,"Report an error");rpb.type="button";rpb.id="reportBtn";rpb.setAttribute("aria-expanded",rep.id===e.id?"true":"false");
    rpb.addEventListener("click",function(){rep=rep.id===e.id?{id:null,text:"",fail:false,busy:false}:{id:e.id,text:"",fail:false,busy:false};render();var t=$("reportText");if(t)t.focus();});
    acts.appendChild(rpb);
    b.appendChild(acts);
    if(rep.id===e.id)b.appendChild(reportForm(e));
    if(e.hunt.length){var hs=el("div","srcs");hs.appendChild(el("span",null,"Detection resources ("+e.hunt.length+"):"));
      e.hunt.forEach(function(x){var l=el("a",null,x.name+" ("+x.fmt+")");l.href=safeUrl(x.url);l.target="_blank";l.rel="noopener noreferrer";hs.appendChild(l);});b.appendChild(hs);}
    if(e.cves.length&&(e.kev||e.category==="vuln")){var wk=el("p","mono");var wa=el("a",null,"Open on the Vulnerabilities page: am I affected, and how to fix");wa.href="vulnerabilities.html#"+encodeURIComponent(e.cves[0]);wk.appendChild(wa);b.appendChild(wk);}
    if(e.attr){var ab=el("div","todo attr");ab.appendChild(el("h4",null,"Attribution"));
      ab.appendChild(el("p",null,"Attributed to "+e.attr.actor+(e.attr.origin?", said to operate from "+e.attr.origin:"")+", by "+e.attr.by+" ("+(e.attr.byType==="government"?"a government body":"the investigating firm")+")."));
      ab.appendChild(el("p","mono","Attribution is a judgement by the named body, not a CyberView finding, and can be disputed."));
      var aa=el("a",null,"Read the attribution");aa.href=safeUrl(e.attr.url);aa.target="_blank";aa.rel="noopener noreferrer";ab.appendChild(aa);b.appendChild(ab);}
    var lks=linksOf(e);
    if(lks.length){var lu=el("ul","rel links");lu.appendChild(el("li",null,"Linked by sources ("+lks.length+"):"));lks.forEach(function(x){var l=el("li");var lb=el("button",null,x.rel+" · "+x.e.title);lb.type="button";
      lb.addEventListener("click",function(){state.day=null;state.spot=null;state.country=null;select(x.e.id,true);});l.appendChild(lb);
      if(x.url){var la=el("a","src",x.src==="source"?"source":"");la.textContent="source";la.href=safeUrl(x.url);la.target="_blank";la.rel="noopener noreferrer";l.appendChild(document.createTextNode(" "));l.appendChild(la);}lu.appendChild(l);});b.appendChild(lu);}
    var rel=related(e).filter(function(o){return !lks.some(function(x){return x.e.id===o.id;});});
    if(rel.length){var ul=el("ul","rel");ul.appendChild(el("li",null,"Related:"));rel.forEach(function(o){var l=el("li");var rb=el("button",null,fmtDay(o.date)+" · "+o.title);rb.type="button";rb.addEventListener("click",function(){state.day=null;state.spot=null;state.country=null;select(o.id,true);});l.appendChild(rb);ul.appendChild(l);});b.appendChild(ul);}
    a.appendChild(b);
  }
  li.appendChild(a);return li;
}
function openSource(e){if(!e||!e.sources.length)return;try{window.open(e.sources[0].url,"_blank","noopener,noreferrer");}catch(x){}}
function reportForm(e){
  var f=el("div","rep"),ta=document.createElement("textarea");ta.id="reportText";ta.value=rep.text;
  if(rep.fail){
    f.appendChild(el("div","msg","The GitHub page didn't open. Copy the report and send it another way."));
    ta.readOnly=true;ta.setAttribute("aria-label","Report text to copy");f.appendChild(ta);
    var cb=el("button","btn","Copy");cb.type="button";cb.id="reportCopy";
    cb.addEventListener("click",function(){
      try{navigator.clipboard.writeText(rep.text).then(function(){toast("Report copied.");},function(){toast("Copy was blocked by the browser. Select the text and copy it by hand.");});}
      catch(x){toast("Copy was blocked by the browser. Select the text and copy it by hand.");}
    });f.appendChild(cb);
    return f;
  }
  ta.maxLength=500;ta.placeholder="What is wrong, and what should it say?";ta.setAttribute("aria-label","Describe the error");
  ta.addEventListener("input",function(){rep.text=ta.value;});f.appendChild(ta);
  var sb=el("button","btn","Report on GitHub");sb.type="button";sb.id="reportSend";
  sb.addEventListener("click",function(){
    var note=rep.text.trim().slice(0,500);
    if(!note){toast("Write a short note first.");return;}
    if(rep.busy)return;rep.busy=true;
    var payload={event_id:e.id,title:e.title,note:note,at:new Date().toISOString()},p;
    try{p=db?db.collection("reports").add(payload):Promise.reject(new Error("no db"));}catch(x){p=Promise.reject(x);}
    Promise.resolve(p).then(function(){rep={id:null,text:"",fail:false,busy:false};toast("Your report is open on GitHub. Submit it there.");render();},
      function(){rep={id:e.id,fail:true,busy:false,text:"Error report\nEvent: "+payload.title+"\nEvent id: "+payload.event_id+"\nNote: "+note+"\nAt: "+payload.at};render();});
  });f.appendChild(sb);
  return f;
}
function showEvent(id){
  var e=id&&events.find(function(x){return x.id===id;});
  if(!e){toast("That event is not loaded in this view.");return;}
  state.day=null;state.spot=null;state.country=null;state.pattern=null;
  if(!visible().some(function(x){return x.id===id;})){render();toast(e.status==="claimed"&&!state.claims?"That event is an unverified claim. Turn on Show unverified claims to see it.":"That event is hidden by the current filters.");return;}
  select(id,true);
}
function renderBrief(){
  var box=$("brief");if(box.hidden)return;   /* a hidden tab is drawn when it is opened (setTab), not on every update */
  box.textContent="";
  if(!daily){box.appendChild(el("div","empty",!loaded&&!unavailable?"Loading":"No brief yet. One is written each morning."));return;}
  var hd=el("section","blk");
  hd.appendChild(el("div","meta","Daily brief"+(daily.date&&isDay(daily.date)?" · "+fmtDay(daily.date):"")+(fmtTime(daily.generated)?" · written "+fmtTime(daily.generated):"")));
  if(daily.headline)hd.appendChild(el("h2","bhd",daily.headline));
  if(daily.summary)hd.appendChild(el("p",null,daily.summary));
  box.appendChild(hd);
  if(!daily.items.length)return;
  var ol=el("ol","bitems");
  daily.items.forEach(function(it,i){
    var li=el("li","pcard");
    li.appendChild(el("h3",null,it.title||"Item "+(i+1)));
    if(it.why)li.appendChild(el("p",null,it.why));
    if(it.action)li.appendChild(el("p","do","What to do: "+it.action));
    if(it.id){
      var a=el("div","acts"),b=el("button",null,"Show event");b.type="button";b.id="brief-show-"+i;
      b.addEventListener("click",function(){showEvent(it.id);});a.appendChild(b);li.appendChild(a);
    }
    ol.appendChild(li);
  });
  box.appendChild(ol);
}
function renderScope(){
  var parts=[];
  if(state.spot)parts.push(state.spot.label||(state.spot.length+" events at one spot"));
  if(state.country){var m=events.find(function(e){return normC(e.country)===state.country;});parts.push("Country: "+(m?m.country:state.country));}
  if(state.day)parts.push(fmtDay(state.day));
  var cp=curPattern();if(cp)parts.push("Pattern: "+cp.title);
  if(state.q)parts.push("Search: "+state.q.slice(0,24));
  if(state.status!=="all")parts.push($("status").selectedOptions[0].textContent);
  if(state.lens!=="all")parts.push($("lens").selectedOptions[0].textContent);
  if(state.sev>1)parts.push(state.sev===3?"High only":"Medium and high");
  if(state.cats.size<CATS.length)parts.push((CATS.length-state.cats.size)+" type"+(CATS.length-state.cats.size>1?"s":"")+" off");
  if(state.wlOnly&&wl.terms.length)parts.push("My environment only");
  $("scope").hidden=!parts.length||!!state.sel;$("scopeText").textContent=parts.join(" · ");
  var note=$("notice"),fr=freshness();
  if(fr&&!unavailable){note.hidden=false;note.textContent=fr;}
  else if(unavailable){note.hidden=false;note.textContent="The latest data could not be loaded. Check your connection and press Refresh.";}
  else if(stale){note.hidden=false;note.textContent="Still waiting for the data store. What's shown may be out of date.";}
  else note.hidden=true;
}
// While searching, say how many older matches the archive holds (the map only carries the last few days).
function archHint(f){
  var q=state.q.trim().toLowerCase();if(q.length<2)return;
  var li=el("li","empty arch-hint");f.appendChild(li);
  loadArchive().then(function(rows){
    if(!li.isConnected||state.q.trim().toLowerCase()!==q)return;
    var inWin={};events.forEach(function(e){if(inWindow(e))inWin[e.id]=1;});
    var n=rows.filter(function(r){return r.status!=="claimed"&&!inWin[r.id]&&r.hay.indexOf(q)>=0;}).length;
    if(!n){li.remove();return;}
    li.appendChild(document.createTextNode("Older matches: "));
    var a=el("a",null,n+" more in the archive");a.href="archive.html#q="+encodeURIComponent(state.q.trim());li.appendChild(a);
  });
}
function renderFeed(list){
  var f=$("feed"),ae=document.activeElement,typing=ae&&ae.id==="reportText"&&!ae.readOnly,ss=typing?ae.selectionStart:0;
  var key=[state.win,state.sev,Array.from(state.cats).join(","),state.lens,state.status,state.sort,state.q,state.day,state.spot&&state.spot.length,state.country,state.pattern,state.claims,state.wlOnly].join("|");
  var anchor=null,ft=0;
  if(!f.hidden&&f.scrollTop>0&&key===feedKey){ft=f.getBoundingClientRect().top;for(var ci=0;ci<f.children.length;ci++){var cr=f.children[ci].getBoundingClientRect();if(cr.bottom>ft+4){var fc=f.children[ci].firstChild;if(fc&&fc.id)anchor={id:fc.id,off:cr.top-ft};break;}}}
  var wAnchor=null;if(!wide&&!f.hidden&&key===feedKey&&window.scrollY>0){for(var wi=0;wi<f.children.length;wi++){var wr=f.children[wi].getBoundingClientRect();if(wr.bottom>0){var wc=f.children[wi].firstChild;if(wc&&wc.id)wAnchor={id:wc.id,top:wr.top};break;}}}
  if(wAnchor)setTimeout(function(){var n=document.getElementById(wAnchor.id),li2=n&&n.parentNode;if(li2){var d=li2.getBoundingClientRect().top-wAnchor.top;if(Math.abs(d)>1)window.scrollBy(0,d);}},0);
  f.textContent="";
  if(typing)setTimeout(function(){var t=$("reportText");if(t&&document.activeElement!==t){t.focus();try{t.setSelectionRange(ss,ss);}catch(x){}}},0);
  if(!loaded&&!unavailable){f.appendChild(el("li","empty","Loading events"));return;}
  if(!list.length){f.appendChild(el("li","empty",events.length?"No events match these filters.":"No events stored yet. The next scheduled sweep will add them."));archHint(f);return;}
  /* phones scroll the whole page, so a long list makes every scroll and redraw slow: show 30 and add more on request */
  if(key!==feedKey)feedLimit=30;
  var li=state.last?list.findIndex(function(x){return x.id===state.last;}):-1;if(li>=feedLimit)feedLimit=li+10;
  var shown=wide?list:list.slice(0,feedLimit);
  var frag=document.createDocumentFragment();
  var ji=justIn(list);if(ji)frag.appendChild(ji);
  shown.forEach(function(e){frag.appendChild(card(e,false));});f.appendChild(frag);
  if(shown.length<list.length){var mo=el("li","more"),mb=el("button","btn ghost","Show "+Math.min(30,list.length-shown.length)+" more ("+(list.length-shown.length)+" left)");mb.type="button";mb.id="feedMore";
    mb.addEventListener("click",function(){feedLimit+=30;renderFeed(lastList);});mo.appendChild(mb);f.appendChild(mo);}
  archHint(f);
  if(key!==feedKey){feedKey=key;if(!f.hidden)f.scrollTop=0;feedTop=0;}
  else if(anchor){var an=$(anchor.id);if(an)f.scrollTop+=an.parentNode.getBoundingClientRect().top-ft-anchor.off;}
}
/* ---------- just in: what was added in the last hours, and what is reported but not yet checked ----------
   New events used to be buried (the list is sorted by priority), and a report only appeared after research reached it.
   The second list is mechanical: publishers' own headlines from the collectors, named and labelled as unchecked. */
var devWire=[],wireOpen=false;
function cleanWire(d){
  var a=d&&Array.isArray(d.items)?d.items:[];
  return a.slice(0,40).map(function(x){
    if(!x||typeof x!=="object")return null;
    var u=str(x.url,600),src=(Array.isArray(x.sources)?x.sources:[]).slice(0,4).map(function(v){return str(v,60);}).filter(Boolean);
    var o={id:str(x.id,12),title:str(x.title,180),sources:src,n:Math.max(1,Math.min(99,Math.round(+x.publishers)||1)),url:/^https:\/\//i.test(u)?u:"",at:str(x.at,30),exploited:x.exploited===true};
    return o.title&&src.length?o:null;}).filter(Boolean);
}
function justIn(list){
  if(state.q||state.day||state.spot||state.country||state.pattern||state.wlOnly||state.lens!=="all"||state.status!=="all"||state.sort!=="pri")return null;
  var cut=Date.now()-12*3600e3;
  var added=list.filter(function(e){return Date.parse(e.firstSeen)>cut;}).sort(function(a,b){return Date.parse(b.firstSeen)-Date.parse(a.firstSeen);}).slice(0,4);
  var dev=devWire.filter(function(x){return Date.now()-Date.parse(x.at)<36*3600e3;});
  if(!added.length&&!dev.length)return null;
  var li=el("li","justin");
  if(added.length){
    li.appendChild(el("h3",null,"Just added"));var ul=el("ul");
    added.forEach(function(e){var r=el("li"),b=el("button",null,e.title);b.type="button";b.addEventListener("click",function(){select(e.id,true);});
      r.appendChild(el("span","when",ago(e.firstSeen)));r.appendChild(b);ul.appendChild(r);});
    li.appendChild(ul);
  }
  if(dev.length){
    li.appendChild(el("h3",null,"Reported, being checked ("+dev.length+")"));
    li.appendChild(el("p","cap","Headlines from the publishers named, as collected. CyberView has not checked these yet; each becomes an event once its source has been read."));
    var ul2=el("ul");
    dev.slice(0,wireOpen?30:3).forEach(function(x){var r=el("li"),t;
      if(x.url){t=el("a",null,x.title);t.href=safeUrl(x.url);t.target="_blank";t.rel="noopener noreferrer";}else t=el("span","t",x.title);
      r.appendChild(t);
      r.appendChild(el("small",null,x.sources.join(", ")+(x.n>x.sources.length?" and "+(x.n-x.sources.length)+" more":"")+(ago(x.at)?" · "+ago(x.at):"")+(x.exploited?" · listed as exploited":"")));
      ul2.appendChild(r);});
    li.appendChild(ul2);
    if(dev.length>3){var mb=el("button","linkbtn",wireOpen?"Show fewer":"Show all "+dev.length);mb.type="button";mb.addEventListener("click",function(){wireOpen=!wireOpen;renderFeed(lastList);});li.appendChild(mb);}
  }
  return li;
}
function renderDetail(list){
  var e=state.sel&&list.find(function(x){return x.id===state.sel;}),on=!!e&&state.tab==="feed";
  var d=$("detail"),f=$("feed"),was=!d.hidden;
  if(on&&!was)feedTop=f.scrollTop;
  $("dbar").hidden=!on;d.hidden=!on;$("listTools").hidden=on||state.tab!=="feed";f.hidden=state.tab!=="feed"||on;
  document.querySelector("#listTools .t2").hidden=state.tab!=="feed";
  if(!on){d.textContent="";d.dataset.id="";if(was&&!f.hidden){f.scrollTop=feedTop;var c=state.last&&$("card-"+state.last);if(c)c.scrollIntoView({block:"nearest"});}return;}
  var ae=document.activeElement,typing=ae&&ae.id==="reportText"&&!ae.readOnly,ss=typing?ae.selectionStart:0,same=d.dataset.id===e.id,st=d.scrollTop;
  d.textContent="";d.appendChild(card(e,true));d.dataset.id=e.id;state.last=e.id;
  if(same)d.scrollTop=st;else{d.scrollTop=0;d.style.animation="none";void d.offsetWidth;d.style.animation="";}
  if(typing){var t=$("reportText");if(t){t.focus();try{t.setSelectionRange(ss,ss);}catch(x){}}}
  var i=list.indexOf(e);$("dPos").textContent=(i+1)+" of "+list.length;$("dPrev").disabled=i<=0;$("dNext").disabled=i>=list.length-1;
}

/* ---------- insights ---------- */
function tally(list,fn){var m=new Map();list.forEach(function(e){var k=fn(e);if(k)m.set(k,(m.get(k)||0)+1);});return Array.from(m).sort(function(a,b){return b[1]-a[1];});}
function bars(title,rows,onPick,fmt){
  var b=el("section","blk");b.appendChild(el("h3",null,title));
  if(!rows.length){b.appendChild(el("div","empty","Nothing in this window."));return b;}
  var max=rows[0][1];
  rows.forEach(function(r){
    var row=el(onPick?"button":"div","brow");if(onPick){row.type="button";row.addEventListener("click",function(){onPick(r[0]);});}
    row.appendChild(el("span",null,r[2]||r[0]));var tr=el("span","tr");var i=el("i");i.style.width=Math.max(4,r[1]/max*100)+"%";tr.appendChild(i);row.appendChild(tr);
    row.appendChild(el("span","v",fmt?fmt(r[1]):String(r[1])));b.appendChild(row);
  });
  return b;
}
function sysRow(dl,k,iso,lateH){
  dl.appendChild(el("dt",null,k));var t=Date.parse(iso),late=isFinite(t)&&lateH&&Date.now()-t>lateH*3600e3;
  dl.appendChild(el("dd",late?"late":null,isFinite(t)?ago(iso)+(late?" (overdue)":""):"not yet run"));
}
function renderInsights(list){
  var box=$("ins");if(box.hidden)return;
  box.textContent="";
  if(!loaded){box.appendChild(el("div","empty",unavailable?"Live data unavailable":"Loading"));return;}
  var k=el("div","kpis");
  function kpi(v,l){var d=el("div","kpi");d.appendChild(el("b",null,v));d.appendChild(el("span",null,l));k.appendChild(d);}
  var corr=list.filter(function(e){return e.val&&e.val.state==="corroborated";}).length;
  kpi(String(list.length),"events");kpi(String(list.filter(function(e){return e.severity===3;}).length),"high severity");
  kpi(String(new Set(list.map(function(e){return normC(e.country);}).filter(Boolean)).size),"countries");
  kpi(list.length?Math.round(corr/list.length*100)+"%":"0%","corroborated");
  box.appendChild(k);
  box.appendChild(histBlock());
  box.appendChild(bars("Source quality",tally(list,function(e){return e.tier?TIER[e.tier]:"Not rated yet";}),null));
  box.appendChild(bars("Validation",tally(list,function(e){return e.val?VAL[e.val.state][0]:"Not yet checked";}),null));
  box.appendChild(bars("Countries",tally(list,function(e){return e.country;}).slice(0,6),function(c){state.country=normC(c);setTab("feed");render();}));
  box.appendChild(bars("Sectors",tally(list,function(e){return e.sector.split(" / ")[0];}).slice(0,6),function(s){state.q=s;$("q").value=s;setTab("feed");render();}));
  box.appendChild(bars("Named actors",tally(list,function(e){return e.actor;}).slice(0,5),function(s){state.q=s.split(" (")[0];$("q").value=state.q;setTab("feed");render();}));
  var big=list.filter(function(e){return e.records;}).sort(function(a,b){return b.records-a.records;}).slice(0,5).map(function(e){return [e.id,e.records,e.org||e.title];});
  box.appendChild(bars("Largest by records affected",big,function(id){setTab("feed");select(id,true);},fmtNum));
  var tg=tally(list.reduce(function(a,e){return a.concat(e.tags.map(function(t){return {t:t};}));},[]),function(x){return x.t;}).slice(0,6);
  if(tg.length)box.appendChild(bars("Tags",tg,function(t){state.q=t;$("q").value=t;setTab("feed");render();}));
  var q=el("section","blk");q.appendChild(el("h3",null,"Data quality"));
  var dq=el("dl","sys");
  function qr(a,b){dq.appendChild(el("dt",null,a));dq.appendChild(el("dd",null,String(b)));}
  qr("Single source",list.filter(function(e){return e.val&&e.val.state==="single_source";}).length);
  qr(state.claims?"Unverified claims shown":"Unverified claims hidden",base(true).filter(function(e){return e.status==="claimed";}).length);
  qr("Not yet checked",list.filter(function(e){return !e.val;}).length);
  qr("No map location",list.filter(function(e){return e.lat===null;}).length);
  qr("Uncertain date",list.filter(function(e){return e.dateNote;}).length);
  q.appendChild(dq);box.appendChild(q);
  var cs=el("section","blk");cs.appendChild(el("h3",null,"Corrections"));
  if(!corrections.length)cs.appendChild(el("div","empty","No corrections recorded yet"));
  else{var cu=el("ul","corr");corrections.forEach(function(c){
    var li=el("li");
    if(c.id&&events.some(function(e){return e.id===c.id;})){var cb=el("button",null,c.title||"Event");cb.type="button";cb.addEventListener("click",function(){showEvent(c.id);});li.appendChild(cb);}
    else li.appendChild(el("b",null,c.title||"Event"));
    if(c.what)li.appendChild(el("div",null,c.what));
    if(fmtTime(c.at))li.appendChild(el("small",null,fmtTime(c.at)));
    cu.appendChild(li);});cs.appendChild(cu);}
  box.appendChild(cs);
  var rb=document.createElement("details");rb.className="blk";rb.id="rubric";rb.open=rubricOpen;
  var sm=el("summary",null,"How severity and confidence are scored");sm.id="rubricToggle";rb.appendChild(sm);
  var ru=el("ul");
  ["Severity 1, low: claims, small breaches, brief glitches.",
   "Severity 2, medium: a confirmed breach, attack or outage with real impact.",
   "Severity 3, high: critical infrastructure, national-scale disruption, exploited zero-days, or millions of records.",
   "Confidence high: corroborated and confirmed.",
   "Confidence medium: a single source, or still developing.",
   "Confidence low: an unverified claim, a disputed report, or a source that could not be reached."].forEach(function(t){ru.appendChild(el("li",null,t));});
  rb.appendChild(ru);rb.addEventListener("toggle",function(){rubricOpen=rb.open;});
  box.appendChild(rb);
  var s=el("section","blk");s.appendChild(el("h3",null,"Update pipeline"));var sd=el("dl","sys");
  [["Hourly sweep","last_sweep_at",3],["Validation pass","last_validation_at",6],["Feeds and scores","last_feeds_at",6],["Known-exploited feed","last_kev_at",6],["Pattern analysis","last_analysis_at",8],["Report review","last_reports_at",26],["Daily deep sweep","last_deep_sweep_at",30],["Daily brief","last_brief_at",30],["Daily cleanup","last_maintenance_at",30]].forEach(function(r){sysRow(sd,r[0],sweep&&sweep[r[1]],r[2]);});
  sd.appendChild(el("dt",null,"Next hourly sweep"));sd.appendChild(el("dd",null,nextSweep()));
  s.appendChild(sd);
  if(sweep&&sweep.health&&typeof sweep.health==="object"&&str(sweep.health.note,200))s.appendChild(el("div","empty",str(sweep.health.note,200)));
  if(sweep&&sweep.coverage_note){s.appendChild(el("div","empty",str(sweep.coverage_note,200)));}
  box.appendChild(s);
  var ab=document.createElement("details");ab.className="blk";ab.id="about";
  ab.appendChild(el("summary",null,"About this map: sources, method and limits"));
  var au=el("ul");
  ["What it is: a rolling seven-day picture of publicly reported cyber events, kept current by scheduled research tasks. It is not a complete record of everything that happened.",
   "Sources: government agencies (CISA, FBI, NSA and counterparts abroad), security vendors' own reports, CISA's known-exploited catalog, NVD and EPSS scores, and established news outlets. Each event lists the sources it rests on.",
   "Verification: a validation pass re-checks events against their sources. Events reviewed against an original government or vendor report carry a report badge. Attacker claims that the named organisation has not confirmed are hidden unless you turn them on.",
   "Outages are recorded as outages and are never described as attacks unless an official source says so.",
   "Corrections: when an original source contradicts an entry, the entry is fixed and the change is listed under Corrections.",
   "Analysis views: patterns, chains and ripple effects are assembled by an analysis pass. Anything marked inferred or reasoned is a judgement, not a reported fact.",
   "Limits: coverage leans toward English-language and government sources; dates are mostly publication dates; counts reflect what was collected. Check the linked source before acting on any single entry.",
   "This is an information aid, not professional security advice for your organisation."].forEach(function(t){au.appendChild(el("li",null,t));});
  ab.appendChild(au);
  box.appendChild(ab);
  box.appendChild(el("div","empty","CyberView version "+BUILD.version+" · built "+fmtDay(BUILD.date)+(sweep&&sweep.data_version?" · data rules "+str(sweep.data_version,20):"")));
  var subs=el("div","empty");subs.appendChild(document.createTextNode("Subscribe to high-priority events: "));var rl=el("a",null,"RSS");rl.href="data/feed.xml";subs.appendChild(rl);subs.appendChild(document.createTextNode(" · "));var jl=el("a",null,"JSON Feed");jl.href="data/feed.json";subs.appendChild(jl);subs.appendChild(document.createTextNode(" · "));var al=el("a",null,"Full archive");al.href="archive.html";subs.appendChild(al);box.appendChild(subs);
}
function histBlock(){
  var b=el("section","blk hist");b.appendChild(el("h3",null,"This week vs earlier"));
  var n=hist?hist.length:0;
  if(n<8){b.appendChild(el("div","empty","Baseline is still being built ("+n+" day"+(n===1?"":"s")+" recorded)"));return b;}
  var Wd=380,Ht=64,max=Math.max(1,d3.max(hist,function(x){return x.n;})),step=Wd/n,bw=Math.max(2,step-2);
  var s=document.createElementNS(NS,"svg");s.setAttribute("viewBox","0 0 "+Wd+" "+(Ht+2));s.setAttribute("role","img");
  var wk=hist.slice(-7),prior=hist.slice(0,-7),wsum=d3.sum(wk,function(x){return x.n;}),pavg=Math.round(d3.sum(prior,function(x){return x.n;})/prior.length*7);
  s.setAttribute("aria-label","Events per day for the last "+n+" recorded days. Last 7 days total "+wsum+".");
  hist.forEach(function(x,i){
    var hgt=Math.max(1.5,x.n/max*Ht),r=document.createElementNS(NS,"rect");
    r.setAttribute("x",(i*step+1).toFixed(1));r.setAttribute("y",(Ht-hgt).toFixed(1));r.setAttribute("width",bw.toFixed(1));r.setAttribute("height",hgt.toFixed(1));r.setAttribute("rx",Math.min(3,bw/2));
    r.setAttribute("class","hb"+(i>=n-7?" wk":""));
    var t=document.createElementNS(NS,"title");t.textContent=fmtDay(x.d)+": "+x.n+" events";r.appendChild(t);s.appendChild(r);
  });
  var l=document.createElementNS(NS,"line");l.setAttribute("class","hbl");l.setAttribute("x1",0);l.setAttribute("x2",Wd);l.setAttribute("y1",Ht+.5);l.setAttribute("y2",Ht+.5);s.appendChild(l);
  var top=el("div","hax");top.appendChild(el("span",null,"events per day, peak "+max));top.appendChild(el("span",null,"dark = last 7 days"));b.appendChild(top);
  b.appendChild(s);
  var ax=el("div","hax");ax.appendChild(el("span",null,fmtDay(hist[0].d)));ax.appendChild(el("span",null,fmtDay(hist[n-1].d)));b.appendChild(ax);
  b.appendChild(el("p",null,"This week: "+wsum+" events. Prior "+(prior.length>=15?"3-week":prior.length+"-day")+" average: "+pavg+" per week."));
  return b;
}
function setTab(t){
  state.tab=t;["brief","feed","kev","pat","ins"].forEach(function(k){$("tab-"+k).setAttribute("aria-selected",t===k?"true":"false");$(k).hidden=t!==k;});
  var l=lastList||[];
  safe("brief",renderBrief);safe("exploited",renderKev);safe("patterns",renderPatterns);safe("insights",function(){renderInsights(l);});
  safe("feed",function(){if(t==="feed")renderFeed(l);renderDetail(l);});
}
var KIND={stated:"Stated by sources",inferred:"Inferred pattern",timing:"Timing only"};
function pickPattern(id,view){state.pattern=state.pattern===id&&!view?null:id;state.spot=null;state.day=null;state.sel=null;if(view)setView(view);else render();}
function renderPatterns(){
  var box=$("pat");if(box.hidden)return;
  box.textContent="";
  if(!analysis||!analysis.patterns.length){box.appendChild(el("div","empty",loaded?"No pattern analysis stored yet. The analysis task writes one every few hours.":"Loading"));return;}
  box.appendChild(el("div","warnbox","Correlation is not causation. Each pattern says whether sources state the link, whether it is an inference from shared attributes, or whether it rests on timing alone. Generated "+(fmtTime(analysis.generated)||"recently")+"."));
  if(analysis.summary){var s=el("div","pcard");s.appendChild(el("h3",null,"Overall read"));s.appendChild(el("p",null,analysis.summary));box.appendChild(s);}
  var byId={};events.forEach(function(e){if(claimOk(e))byId[e.id]=e;});
  analysis.patterns.forEach(function(p){
    var have=p.ids.filter(function(i){return byId[i];});
    var c=el("div","pcard"+(state.pattern===p.id?" on":""));
    var hd=el("div","meta");hd.appendChild(el("span","pk "+p.kind,KIND[p.kind]));hd.appendChild(el("span",null,"confidence "+CONF[p.conf].toLowerCase()));hd.appendChild(el("span",null,have.length+" events"));
    c.appendChild(hd);c.appendChild(el("h3",null,p.title));c.appendChild(el("p",null,p.narrative));
    if(p.caveat)c.appendChild(el("p","cav",p.caveat));
    var seq=(p.chain.length?p.chain:have.slice().sort(function(a,b){return byId[a].t-byId[b].t;})).filter(function(i){return byId[i];});
    if(seq.length){var ol=el("ol");seq.slice(0,14).forEach(function(i){var e=byId[i],li=el("li"),b=el("button",null,e.org||e.title);b.type="button";
      b.addEventListener("click",function(){state.pattern=p.id;setTab("feed");select(i,true);});li.appendChild(b);li.appendChild(el("small",null,"  "+fmtWhen(e)));ol.appendChild(li);});c.appendChild(ol);}
    var acts=el("div","acts");
    if(seq.length>1&&replaySteps(p).filter(function(x){return x.lat!==null;}).length>1){var rb=el("button","primary","Replay on globe");rb.type="button";rb.title="Watch this pattern unfold step by step on the globe";rb.addEventListener("click",function(){replayStart(p.id);});acts.appendChild(rb);}
    [["Show on map","map"],["Timeline","time"],["Correlation view","graph"]].forEach(function(a){var b=el("button",null,a[0]);b.type="button";b.addEventListener("click",function(){pickPattern(p.id,a[1]);});acts.appendChild(b);});
    if(state.pattern===p.id){var x=el("button",null,"Clear");x.type="button";x.addEventListener("click",function(){state.pattern=null;render();});acts.appendChild(x);}
    c.appendChild(acts);box.appendChild(c);
  });
}

/* ---------- map ---------- */
var svg=d3.select("#svg"),gMap=svg.append("g"),gArcs=svg.append("g").attr("class","arcs"),gMarks=svg.append("g").attr("filter","url(#glow)");
/* the globe; proj() hides points on the far side */
var globeProj=d3.geoOrthographic().clipAngle(90).precision(.4),globe=true,ROT0=[30,-28],rot=ROT0.slice(),spin=null,raf2=0;
var projection=globeProj.rotate(rot),path=d3.geoPath(projection),T=d3.zoomIdentity,W=800,H=450,FX=400,FY=225,FW=600,FH=300,world=null,raf=0;
var MAXK=60,R=17,wide=true;
var zoom=d3.zoom().scaleExtent([.8,MAXK]).filter(function(ev){return state.view!=="time"&&(!ev.ctrlKey||ev.type==="wheel")&&!ev.button&&(!globe||ev.type==="wheel"||!!(ev.touches&&ev.touches.length>1));}).on("zoom",function(ev){T=ev.transform;
  if(globe&&ev.sourceEvent){T=d3.zoomIdentity.translate(FX*(1-T.k),FY*(1-T.k)).scale(T.k);svg.node().__zoom=T;}
  gMap.attr("transform",T);if(!raf)raf=requestAnimationFrame(function(){raf=0;drawMarks();});});
svg.call(zoom).on("dblclick.zoom",null);
function layout(){
  var r=$("stage").getBoundingClientRect();W=Math.max(200,r.width);H=Math.max(160,r.height);
  wide=!(window.matchMedia&&matchMedia("(max-width:900px),(max-height:520px) and (pointer:coarse)").matches);
  var hh=document.querySelector("header").getBoundingClientRect().height,dh=$("days").getBoundingClientRect().height;
  document.documentElement.style.setProperty("--hdr",hh+"px");
  var x0=wide?60:8,y0=wide?hh+34:8,x1=wide?W-430-34:W-8,y1=wide?H-dh-34:H-8;
  if(wall.on){x0=W>900?W*.2:16;x1=W>900?W*.8:W-16;y0=W>900?96:200;y1=H-(W>900?150:250);}
  if(x1-x0<160){x0=8;x1=W-8;} if(y1-y0<120){y0=8;y1=H-8;}
  FX=(x0+x1)/2;FY=(y0+y1)/2;FW=x1-x0;FH=y1-y0;
  svg.attr("viewBox","0 0 "+W+" "+H);
  gMarks.attr("filter",coarse||!wide?null:"url(#glow)");   /* the soft glow is costly to repaint on phones */
  /* d3.drag sets touch-action:none on the element itself; on the phone layout an up or down swipe must scroll the page */
  svg.style("touch-action",wide||wall.on?"none":"pan-y");
  projection.fitExtent([[x0,y0],[x1,y1]],{type:"Sphere"});
  zoom.translateExtent([[-W*.6,-H*.6],[W*1.6,H*1.6]]).extent([[0,0],[W,H]]);
  gMap.selectAll("*").remove();
  if(globe)gMap.append("path").attr("class","ocean").datum({type:"Sphere"}).attr("d",path);
  gMap.append("path").attr("class","grat").datum(d3.geoGraticule10()).attr("d",path);
  gMap.append("path").attr("class","sphere").datum({type:"Sphere"}).attr("d",path);
  if(world)gMap.selectAll("path.country").data(world).join("path").attr("class","country").attr("d",path)
    .on("click",function(ev,f){var n=normC(f.properties.name);if(!f.__n||lastPointer==="touch")return;state.country=state.country===n?null:n;state.spot=null;render();})
    .append("title").text(function(f){return f.properties.name;});
  svg.call(zoom.transform,d3.zoomIdentity);
  shade();
}
/* Redrawing the land is the expensive part of every frame. Two savings, both invisible:
   countries wholly on the far side are skipped, and while the globe is moving outlines are drawn without the
   curve-smoothing pass (it is put back the moment the globe comes to rest, in settle()). */
var lastPointer="";document.addEventListener("pointerdown",function(ev){lastPointer=ev.pointerType||"";},{passive:true,capture:true});
var coarse=!!(window.matchMedia&&matchMedia("(pointer:coarse)").matches),moving=false,settleT=0,lastFrame=0;
/* a lighter copy of each outline (every third point of long rings) for frames drawn while the globe is moving */
function thin(ring,k){if(ring.length<16)return ring;var out=[];for(var i=0;i<ring.length-1;i+=k)out.push(ring[i]);out.push(ring[ring.length-1]);return out.length>=4?out:ring;}
function thinGeom(g,k){
  if(!g)return g;
  if(g.type==="Polygon")return {type:"Polygon",coordinates:g.coordinates.map(function(r){return thin(r,k);})};
  if(g.type==="MultiPolygon")return {type:"MultiPolygon",coordinates:g.coordinates.filter(function(p){return p[0].length>=8;}).map(function(p){return p.map(function(r){return thin(r,k);});})};
  return g;
}
var gratLite=d3.geoGraticule().step([30,30]).precision(12)();
var liteLevel=1,workMs=0;   /* 1 = every third point; 2 = every sixth, used only when frames are taking too long on this device */
function prepWorld(){if(!world)return;var k=3;world.forEach(function(f){var c=d3.geoCentroid(f),b=d3.geoBounds(f),r=0;
  [[b[0][0],b[0][1]],[b[1][0],b[1][1]],[b[0][0],b[1][1]],[b[1][0],b[0][1]]].forEach(function(q){var d=d3.geoDistance(c,q);if(d>r)r=d;});f.__c=c;f.__r=Math.min(Math.PI,r+.12);
  var lg=thinGeom(f.geometry,k),lg2=thinGeom(f.geometry,6);f.__lite=lg&&lg.coordinates&&lg.coordinates.length?{type:"Feature",geometry:lg}:null;
  f.__lite2=lg2&&lg2.coordinates&&lg2.coordinates.length?{type:"Feature",geometry:lg2}:f.__lite;});}
function repath(fast){
  fast=!!fast;if(fast!==moving){moving=fast;globeProj.precision(fast?0:.4);}
  var centre=[-rot[0],-rot[1]];
  gMap.selectAll("path").attr("d",function(f){
    if(f&&f.__c)return d3.geoDistance(f.__c,centre)>Math.PI/2+f.__r?"":path(fast&&f.__lite?(liteLevel===2?f.__lite2:f.__lite):f);
    return fast&&f&&f.type==="MultiLineString"?path(gratLite):path(f);});
}
/* one redraw per animation frame while the globe moves (30 a second on phones); settle() restores full quality */
function frame(){
  if(raf2)return;
  raf2=requestAnimationFrame(function(now){raf2=0;
    if(coarse&&now-lastFrame<30){frame();return;}lastFrame=now;
    var w0=performance.now();repath(true);drawMarks();
    /* if this device needs more than about 26 ms of work per frame, use the lighter outlines from now on */
    workMs=workMs?workMs*.85+(performance.now()-w0)*.15:performance.now()-w0;if(liteLevel===1&&workMs>26)liteLevel=2;
    clearTimeout(settleT);settleT=setTimeout(settle,160);});
}
function settle(){if(spin||flyT||raf2){clearTimeout(settleT);settleT=setTimeout(settle,200);return;}if(moving){repath(false);drawMarks();}}
var RAD=Math.PI/180,cv=[0,0,0],cvKey="";
// far side test: dot product with the view centre (cos 87 deg), cheaper than a great-circle distance per point
function proj(lng,lat){
  if(globe){var k=rot[0]+","+rot[1];if(k!==cvKey){cvKey=k;var l0=-rot[0]*RAD,p0=-rot[1]*RAD;cv=[Math.cos(p0)*Math.cos(l0),Math.cos(p0)*Math.sin(l0),Math.sin(p0)];}
    var l=lng*RAD,p=lat*RAD,cp=Math.cos(p);if(cp*Math.cos(l)*cv[0]+cp*Math.sin(l)*cv[1]+Math.sin(p)*cv[2]<0.0506)return null;}
  return projection([lng,lat]);
}
function turnTo(lng,lat){stopSpin();rot=[-lng,Math.max(-70,Math.min(70,-lat))];globeProj.rotate(rot);repath(false);}
function stopSpin(){if(spin){spin.stop();spin=null;}}
var stageSeen=true;
function startSpin(){
  /* phones: no automatic spin. Each spin frame is a long task on a phone, so the first seconds of a visit felt frozen;
     the globe turns with a swipe instead (wall mode still spins) */
  if(reduced||spin||!globe||!stageSeen||(coarse&&!wall.on))return;
  /* by the clock, not by the frame: a slow phone drops frames but the globe still turns at the same speed (3.6 degrees a second) */
  var last=-1;
  spin=d3.timer(function(t){if(!globe||(t>(coarse||!wide?12000:45000)&&!wall.on)||document.hidden||state.view!=="map"||rp.on){stopSpin();settle();return;}
    var dt=last<0?16:Math.min(120,t-last);last=t;rot[0]+=dt*.0036;
    globeProj.rotate(rot);frame();});
}
/* the map is always a globe: Refresh turns it back to the starting view and lets it spin again */
function resetGlobe(){stopSpin();rot=ROT0.slice();globeProj.rotate(rot);repath(false);drawMarks();startSpin();}
document.body.classList.add("globe");
// drag turns the globe (the flat map pans with d3.zoom instead)
function turnBy(dx,dy){var d=180/(Math.PI*globeProj.scale()*T.k);rot=[rot[0]+dx*d,Math.max(-80,Math.min(80,rot[1]-dy*d))];globeProj.rotate(rot);frame();}
/* mouse, pen, and touch on wide screens: drag turns the globe. On the phone layout the page scrolls, so one-finger
   touches are handled below instead: a sideways swipe turns the globe, an up or down swipe scrolls the page. */
svg.call(d3.drag().filter(function(ev){var touch=/^touch/.test(ev.type)||ev.pointerType==="touch";return globe&&state.view==="map"&&!ev.button&&!(ev.touches&&ev.touches.length>1)&&!(touch&&!wide);})
  .on("start",function(){stopSpin();hideTip();})
  .on("drag",function(ev){turnBy(ev.dx,ev.dy);}));
var tg=null;
$("svg").addEventListener("touchstart",function(ev){tg=!wide&&globe&&state.view==="map"&&ev.touches.length===1?{x:ev.touches[0].clientX,y:ev.touches[0].clientY,mode:""}:null;},{passive:true});
$("svg").addEventListener("touchmove",function(ev){
  if(!tg||ev.touches.length!==1){tg=null;return;}
  var t=ev.touches[0],dx=t.clientX-tg.x,dy=t.clientY-tg.y;
  if(!tg.mode){if(Math.abs(dx)<7&&Math.abs(dy)<7)return;tg.mode=Math.abs(dx)>=Math.abs(dy)?"turn":"scroll";if(tg.mode==="turn"){stopSpin();hideTip();}}
  if(tg.mode!=="turn")return;
  if(ev.cancelable)ev.preventDefault();
  tg.x=t.clientX;tg.y=t.clientY;turnBy(dx,dy);
},{passive:false});
["touchend","touchcancel"].forEach(function(n){$("svg").addEventListener(n,function(){tg=null;},{passive:true});});
$("svg").addEventListener("wheel",stopSpin,{passive:true,capture:true});
/* While the globe moves, its markers are redrawn every frame, so a tap would land on a marker that is gone a moment later.
   The first touch or press freezes the globe exactly as it is; quality is restored after the tap has had time to finish. */
function freeze(){var was=!!(spin||raf2||flyT&&!rp.on&&!wall.on);stopSpin();if(raf2){cancelAnimationFrame(raf2);raf2=0;}clearTimeout(settleT);if(was||moving)settleT=setTimeout(settle,700);}
$("svg").addEventListener("pointerdown",freeze,{passive:true,capture:true});
$("svg").addEventListener("touchstart",freeze,{passive:true,capture:true});
/* the spin is decoration: it stops for good as soon as the reader scrolls or the globe leaves the screen */
if(window.IntersectionObserver)new IntersectionObserver(function(en){stageSeen=en[0].isIntersecting;if(!stageSeen&&!wall.on){stopSpin();settle();}},{threshold:.15}).observe($("stage"));
var toMapT=0;
window.addEventListener("scroll",function(){if(wide)return;if(spin&&window.scrollY>40){stopSpin();settle();}
  if(!toMapT)toMapT=requestAnimationFrame(function(){toMapT=0;$("toMap").hidden=window.scrollY<520||wall.on;});},{passive:true});
$("toMap").addEventListener("click",function(){window.scrollTo(0,0);});
function shade(){
  if(!world)return;
  var counts=new Map();scoped().forEach(function(e){var n=normC(e.country);if(n)counts.set(n,(counts.get(n)||0)+1);});
  var dis=new Map();if(ctxOn.ioda&&ctx.ioda)ctx.ioda.items.forEach(function(x){if(x.map)dis.set(x.map,x);});
  gMap.selectAll("path.country").each(function(f){
    var n=normC(f.properties.name),c=counts.get(n)||0;f.__n=c;
    d3.select(this).classed("has",c>0).classed("on",state.country===n)
      .style("fill",c?"color-mix(in srgb,var(--accent) "+Math.min(46,10+c*6)+"%,var(--land))":null);
    var dx=dis.get(f.properties.name.toLowerCase());d3.select(this).classed("dis",!!dx);
    d3.select(this).select("title").text(f.properties.name+(c?": "+c+" events":"")+(dx?" · internet disruption signal in the last 24 h (IODA: "+dx.signals.join(", ")+"; not an attack report)":""));
  });
}
function clusters(list){
  var pts=[];
  list.forEach(function(e){
    if(e.lat===null)return;var p=proj(e.lng,e.lat);if(!p)return;
    pts.push({e:e,bx:p[0],by:p[1],x:T.applyX(p[0]),y:T.applyY(p[1])});
  });
  pts.sort(function(a,b){return b.e.severity-a.e.severity||(a.e.date<b.e.date?1:-1);});
  var cs=[];
  pts.forEach(function(p){
    for(var i=0;i<cs.length;i++){if(Math.hypot(cs[i].x-p.x,cs[i].y-p.y)<R){cs[i].items.push(p);return;}}
    cs.push({x:p.x,y:p.y,items:[p]});
  });
  return cs;
}
var lastList=[];
function setView(v){
  state.view=v;document.querySelectorAll("[data-view]").forEach(function(x){x.setAttribute("aria-pressed",x.dataset.view===v?"true":"false");});
  gMap.style("display",v==="map"?null:"none");
  document.querySelector(".zoomer").style.display=v==="map"?"":"none";if(v!=="map"){stopSpin();if(!$("layers").hidden)layersToggle(false);}$("key").style.display=v==="map"?"":"none";
  $("viz").hidden=v==="map";$("viz").scrollTop=0;document.body.dataset.view=v;
  svg.call(zoom.transform,d3.zoomIdentity);render();
}
function rings(g,e,k){
  if(e.actorPin)g.append("circle").attr("class","act").attr("r",11*k);
  else if(e.countryPin)g.append("circle").attr("class","ctry").attr("r",11*k);
  if(e.wl)g.append("circle").attr("class","wlr").attr("r",(e.actorPin||e.countryPin?14.5:12.5)*k);
}
function pinNote(e){return e.actorPin?" · attributed origin, not a victim location":e.countryPin?" · country-level location":"";}
function winDays(){var a=[];for(var i=state.win-1;i>=0;i--)a.push(ymd(daysAgo(i)));return a;}
function isFiltered(){return !!(state.q||state.status!=="all"||state.lens!=="all"||state.sev>1||state.cats.size<CATS.length||state.wlOnly||state.day||state.spot||state.country||state.pattern);}
function tipAt(ev,a,b){var t=$("tip"),s=$("stage").getBoundingClientRect();t.textContent="";t.appendChild(document.createTextNode(a));if(b)t.appendChild(el("small",null,b));
  t.style.left=Math.min(s.width-140,Math.max(140,ev.clientX-s.left))+"px";t.style.top=Math.max(50,ev.clientY-s.top)+"px";t.style.display="block";}
function seg(opts,cur,label,fn){var s=el("div","seg");s.setAttribute("role","group");s.setAttribute("aria-label",label);
  opts.forEach(function(o){var b=el("button",null,o[1]);b.type="button";b.setAttribute("aria-pressed",o[0]===cur?"true":"false");b.addEventListener("click",function(){fn(o[0]);});s.appendChild(b);});return s;}
function evGlyph(g,e,x,y,small){
  var n=g.append("g").attr("class","ev"+"").attr("transform","translate("+x+","+y+")").attr("tabindex",0).attr("role","button").attr("aria-label",e.title);
  if(state.sel===e.id)n.append("circle").attr("class","selr").attr("r",small?8.5:10);
  else if(e.wl)n.append("circle").attr("class","wlr").attr("r",small?8:9.5);
  n.append("path").attr("d",symPath(e.category,(small?[0,30,46,66]:[0,40,66,100])[e.severity]))
    .attr("fill",e.status==="claimed"?"var(--solid)":"var(--c-"+e.category+")").style("stroke","var(--c-"+e.category+")").style("stroke-width",e.status==="claimed"?1.8:.6);
  n.on("click",function(){select(e.id,false);}).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();select(e.id,false);}})
   .on("pointerenter",function(ev){tipAt(ev,e.title,fmtDay(e.date)+" · "+CAT[e.category].one+" · "+["","low","medium","high"][e.severity]+" severity"+(e.status==="claimed"?" · unverified claim":"")+"");}).on("pointerleave",hideTip);
}
function pickSet(ids,label){var a=ids.slice();a.label=label;state.spot=a;state.sel=null;state.day=null;setTab("feed");render();}
/* ---------- making the long analysis views quick to read ----------
   Both views are several screens of charts. vizShape adds, on top of what vizTime and vizCorr drew: a short summary in
   plain sentences computed from the same events, a bar to jump between sections, sections that fold, and long card lists
   cut to the first three with the rest one tap away. It changes how the content is laid out, never the content. */
var vizUi={closed:{},all:{},open:{}};
var VNAMES={time:["Tempo","Pressure","Patch deadlines"],graph:["Ripple effects","Threat to target","Chains","Shared factors","Hot spots"]};
function vizTakes(list){
  var out=[],hi=function(a){return a.filter(function(e){return e.severity===3;}).length;},plural=function(n,w){return n+" "+w+(n===1?"":"s");};
  if(state.view==="time"){
    var byDay=tally(list,function(e){return e.date;});
    if(byDay.length){var d=byDay[0][0],on=list.filter(function(e){return e.date===d;});out.push([0,"Busiest day: "+fmtDay(d)+", with "+plural(on.length,"event")+" ("+hi(on)+" high severity)."]);}
    var keyOf=viz.lane==="type"?function(e){return e.category;}:viz.lane==="sector"?function(e){return e.secg;}:function(e){return e.layer;},names={};
    (viz.lane==="type"?CATS.map(function(c){return [c.k,c.label];}):viz.lane==="sector"?SECG:LAYERS).forEach(function(l){names[l[0]]=String(l[1]).split(":")[0];});
    var lanes=tally(list.filter(function(e){return e.severity===3&&(viz.lane!=="layer"||e.layer!=="org");}),keyOf);
    if(lanes.length&&names[lanes[0][0]]){var all=list.filter(function(e){return keyOf(e)===lanes[0][0];}).length;out.push([1,names[lanes[0][0]]+" carries the most high-severity events: "+lanes[0][1]+" of its "+all+"."]);}
    var due=kev.map(function(k){return {k:k,left:kevLeft(k)};}).filter(function(x){return x.left!==null;}),late=due.filter(function(x){return x.left<0;}).length,soon=due.filter(function(x){return x.left>=0&&x.left<=7;}).sort(function(a,b){return a.left-b.left;});
    if(soon.length||late)out.push([2,(soon.length?plural(soon.length,"known-exploited flaw")+(soon.length===1?" has":" have")+" a US federal patch deadline within 7 days; the nearest is "+soon[0].k.cve+(soon[0].left===0?" today":" in "+plural(soon[0].left,"day"))+".":"No federal patch deadline falls in the next 7 days.")+(late?" "+late+" on file "+(late===1?"is":"are")+" already past the deadline.":"")]);
    var fresh=list.filter(function(e){return Date.now()-Date.parse(e.firstSeen)<864e5;}).length;
    if(fresh)out.push([-1,plural(fresh,"event")+" added to the map in the last 24 hours."]);
  }else{
    var byId={};list.forEach(function(e){byId[e.id]=e;});
    var rp=ripples?ripples.items.filter(function(r){return byId[r.id];}):[];
    if(rp.length)out.push([0,plural(Math.min(6,rp.length),"event")+" with the widest reach "+(rp.length===1?"has":"have")+" a written what-follows analysis, starting with: "+byId[rp[0].id].title+"."]);
    var tags=tally(list.reduce(function(a,e){if(e.layer!=="org")e.tags.forEach(function(t){a.push(t);});return a;},[]),function(t){return t;});
    if(tags.length)out.push([1,"Most common kind of threat: "+tags[0][0]+" ("+plural(tags[0][1],"event")+")"+(tags[1]?", then "+tags[1][0]+" ("+tags[1][1]+")":"")+"."]);
    var pats=analysis?analysis.patterns.filter(function(p){return (p.chain.length>1?p.chain:p.ids).filter(function(i){return byId[i];}).length>=2;}):[];
    if(pats.length){var st=pats.filter(function(p){return p.kind==="stated";});out.push([2,plural(pats.length,"chain")+" link separate events"+(st.length?"; "+st.length+" rest"+(st.length===1?"s":"")+" on links the sources state":"; none is stated outright by a source")+". First: "+pats[0].title+"."]);}
    var g={};list.forEach(function(e){var seen={};e.cves.concat(e.products.map(function(x){return x.slice(0,40);})).concat(e.actor&&!/^(unknown|unattributed|none|n\/a)/i.test(e.actor)?[e.actor.split(/[;(]/)[0].trim().slice(0,40)]:[]).forEach(function(k){if(k&&!seen[k]){seen[k]=1;g[k]=(g[k]||0)+1;}});});
    var top=Object.keys(g).filter(function(k){return g[k]>1;}).sort(function(a,b){return g[b]-g[a];})[0];
    if(top)out.push([3,"Most widely shared factor: "+top+", named in "+g[top]+" separate events."]);
    var ln={},sn={};LAYERS.forEach(function(l){ln[l[0]]=String(l[1]).split(":")[0];});SECG.forEach(function(x){sn[x[0]]=x[1];});
    var cell=tally(list.filter(function(e){return e.layer!=="org"&&ln[e.layer]&&sn[e.secg];}),function(e){return e.layer+"|"+e.secg;})[0];
    if(cell){var cp=cell[0].split("|");out.push([4,"Where most events land: "+ln[cp[0]]+" in "+sn[cp[1]].toLowerCase()+" ("+plural(cell[1],"event")+")."]);}
  }
  return out;
}
function vizShape(v,list){
  var view=state.view,names=VNAMES[view]||[],secs=Array.prototype.slice.call(v.querySelectorAll(":scope > .vsec")),bodies=[];
  function setOpen(i,on){var b=bodies[i];if(!b)return;b.body.hidden=!on;b.btn.setAttribute("aria-expanded",on?"true":"false");vizUi.closed[view+i]=!on;}
  function go(i){setOpen(i,true);var n=secs[i];if(n){try{n.scrollIntoView({block:"start",behavior:reduced?"auto":"smooth"});}catch(x){n.scrollIntoView();}}}
  secs.forEach(function(sec,i){
    var h=sec.querySelector(":scope > h3, :scope > .vhead > h3");if(!h)return;
    var top=h.parentNode===sec?h:h.parentNode,body=el("div","vbody");while(top.nextSibling)body.appendChild(top.nextSibling);sec.appendChild(body);
    var btn=el("button","vtog");btn.type="button";btn.appendChild(el("span","vn",names[i]||""));btn.appendChild(el("span","vq",h.textContent));h.textContent="";h.appendChild(btn);
    var k=view+i,closed=own(vizUi.closed,k)?vizUi.closed[k]:(!wide&&i>0);
    bodies[i]={body:body,btn:btn};body.hidden=closed;btn.setAttribute("aria-expanded",closed?"false":"true");
    btn.addEventListener("click",function(){setOpen(i,body.hidden);});
    sec.id="vsec-"+view+"-"+i;
  });
  /* long card lists: the first three, the rest on request */
  [[".rips",".rip","analyses"],[".chains",".chain","chains"]].forEach(function(d){
    var box=v.querySelector(d[0]);if(!box)return;var items=Array.prototype.slice.call(box.querySelectorAll(":scope > "+d[1])),k=view+d[0];
    if(items.length>3&&!vizUi.all[k]){items.slice(3).forEach(function(n){n.hidden=true;});
      var mb=el("button","btn ghost sm vmore","Show all "+items.length+" "+d[2]);mb.type="button";mb.addEventListener("click",function(){vizUi.all[k]=true;items.forEach(function(n){n.hidden=false;});mb.remove();});box.appendChild(mb);}
  });
  /* what-follows cards open one at a time: the title and the direct effect first, the rest on request */
  Array.prototype.forEach.call(v.querySelectorAll(".rip"),function(c){
    var cols=c.querySelector(".cols"),t=c.querySelector(".rh button"),first=c.querySelector(".col li");if(!cols||!t)return;
    var k=t.textContent.slice(0,80),open=!!vizUi.open[k],tease=el("p","tease",first?first.textContent:""),tb=el("button","linkbtn",open?"Show less":"What it can lead to and what to watch for");tb.type="button";
    tb.setAttribute("aria-expanded",open?"true":"false");cols.hidden=!open;tease.hidden=open;
    tb.addEventListener("click",function(){var on=cols.hidden;cols.hidden=!on;tease.hidden=on;vizUi.open[k]=on;tb.textContent=on?"Show less":"What it can lead to and what to watch for";tb.setAttribute("aria-expanded",on?"true":"false");});
    c.insertBefore(tease,cols);c.appendChild(tb);
  });
  /* the summary and the jump bar */
  var head=v.querySelector(":scope > .vhead"),takes=[];try{takes=vizTakes(list);}catch(x){takes=[];}
  var nav=el("nav","vnav");nav.setAttribute("aria-label","Sections of this view");
  secs.forEach(function(sec,i){if(!bodies[i])return;var b=el("button",null,names[i]||("Section "+(i+1)));b.type="button";b.addEventListener("click",function(){go(i);});nav.appendChild(b);});
  var all=el("button","ghost",(secs.some(function(x,i){return bodies[i]&&bodies[i].body.hidden;})?"Open all":"Fold all"));all.type="button";
  all.addEventListener("click",function(){var open=all.textContent==="Open all";secs.forEach(function(x,i){setOpen(i,open);});all.textContent=open?"Fold all":"Open all";});nav.appendChild(all);
  var anchor=head?head.nextSibling:v.firstChild;
  if(takes.length){var box=el("section","vtake");box.appendChild(el("h3",null,"In short"));var ul=el("ul");
    takes.forEach(function(t){var li=el("li");li.appendChild(el("span",null,t[1]));if(t[0]>=0&&bodies[t[0]]){var jb=el("button","linkbtn","See "+(names[t[0]]||"section").toLowerCase());jb.type="button";jb.addEventListener("click",function(){go(t[0]);});li.appendChild(jb);}ul.appendChild(li);});
    box.appendChild(ul);box.appendChild(el("p","cav","Computed from the "+list.length+" events in this view; change the filters and it changes with them."));v.insertBefore(box,anchor);}
  v.insertBefore(nav,anchor);
}
function renderViz(list){
  var v=$("viz"),st=v.dataset.view===state.view?v.scrollTop:0;v.dataset.view=state.view;v.textContent="";
  if(!loaded){v.appendChild(el("p","vnone","Loading events"));return;}
  try{if(state.view==="time")vizTime(v,list);else vizCorr(v,list);if(list.length)vizShape(v,list);}
  catch(x){v.appendChild(el("p","vnone","This chart could not be drawn. The charts above it and the rest of the page are unaffected."));throw x;}
  v.scrollTop=st;
}
function vizTime(v,list){
  var days=winDays(),W0=Math.max(560,v.clientWidth-36),LW=Math.min(210,Math.max(170,W0*.22)),CW=(W0-LW)/days.length,today=ymd(new Date());
  var X=function(d){return LW+days.indexOf(d)*CW;};
  var fit=function(t,px,w){var n=Math.max(4,Math.floor(w/px));return t.length>n?t.slice(0,n-1)+"…":t;};
  var hd=el("div","vhead");hd.appendChild(el("h2",null,"Timeline"));
  hd.appendChild(seg([["layer","By attack surface"],["type","By event type"],["sector","By sector"]],viz.lane,"Group rows by",function(k){viz.lane=k;render();}));v.appendChild(hd);
  if(!list.length){v.appendChild(el("p","vnone","No events match these filters."));return;}
  /* 1. tempo */
  var s1=el("div","vsec");s1.appendChild(el("h3",null,"Is this week busier than usual?"));
  var per=days.map(function(d){var o={d:d,t:0};CATS.forEach(function(c){o[c.k]=0;});list.forEach(function(e){if(e.date===d){o[e.category]++;o.t++;}});return o;});
  var base=null;
  if(hist&&!isFiltered()){var vals=hist.filter(function(x){return x.d<days[0];}).map(function(x){return x.n;});
    if(vals.length>=7){var m=d3.mean(vals),sd=d3.deviation(vals)||0;base={m:m,sd:sd,n:vals.length};}}
  var mx=Math.max(d3.max(per,function(p){return p.t;})||1,base?base.m+base.sd:0),TH=104,y=d3.scaleLinear().domain([0,mx]).range([TH,22]),BW=Math.min(24,CW*.5);
  var sv=d3.select(s1).append("svg").attr("viewBox","0 0 "+W0+" "+(TH+22)).attr("role","img").attr("aria-label","Events per day");
  sv.append("text").attr("class","lbl").attr("x",0).attr("y",30).text("Events per day");
  sv.append("text").attr("class","sublbl").attr("x",0).attr("y",46).text(isFiltered()?"filters applied":"all events in the window");
  sv.append("line").attr("class","gl").attr("x1",LW).attr("x2",W0).attr("y1",TH).attr("y2",TH);
  if(base){sv.append("line").attr("class","gl ref").attr("x1",LW).attr("x2",W0).attr("y1",y(base.m)).attr("y2",y(base.m));
    sv.append("text").attr("class","ax").attr("x",LW-8).attr("y",y(base.m)+3.5).attr("text-anchor","end").text("typical day "+base.m.toFixed(1));}
  per.forEach(function(p){var cx=X(p.d)+CW/2,x=cx-BW/2,top=y(p.t),hgt=TH-top,r=Math.min(4,hgt),hot=base&&p.t>base.m+2*base.sd;
    var g=sv.append("g").attr("class","col"+(state.day&&state.day!==p.d?" off":"")).attr("tabindex",0).attr("role","button").attr("aria-label",p.t+" events on "+fmtDay(p.d)+(hot?", unusually high":""));
    g.append("rect").attr("class","hit").attr("x",X(p.d)+2).attr("y",8).attr("width",CW-4).attr("height",TH+12).attr("rx",6);
    if(p.t)g.append("path").attr("class","bar").attr("d","M"+x+","+TH+"V"+(top+r)+"q0,"+(-r)+" "+r+","+(-r)+"h"+(BW-2*r)+"q"+r+",0 "+r+","+r+"V"+TH+"Z");
    g.append("text").attr("x",cx).attr("y",top-6).attr("text-anchor","middle").attr("font-size",11.5).attr("font-weight",600).text(p.t+(hot?" ▲":""));
    g.append("text").attr("class","ax").attr("x",cx).attr("y",TH+15).attr("text-anchor","middle").attr("font-weight",p.d===today?700:400).text(p.d===today?"Today":parseDay(p.d).toLocaleDateString(undefined,{weekday:"short",day:"numeric"}));
    var parts=CATS.filter(function(c){return p[c.k];}).map(function(c){return p[c.k]+" "+c.label.toLowerCase();}).join(" · ");
    var go=function(){state.day=state.day===p.d?null:p.d;render();};
    g.on("click",go).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();go();}})
     .on("pointermove",function(ev){tipAt(ev,p.t+(p.t===1?" event":" events")+" · "+fmtDay(p.d),(parts||"nothing collected")+(hot?" · more than two standard deviations above the usual":""));}).on("pointerleave",hideTip)
     .on("focus",function(){var r2=this.getBoundingClientRect();tipAt({clientX:r2.left+r2.width/2,clientY:r2.top+20},p.t+(p.t===1?" event":" events")+" · "+fmtDay(p.d),parts||"nothing collected");}).on("blur",hideTip);});
  s1.appendChild(el("p","cav","Counts are events this map collected, not every event in the world. Most are dated by publication, so weekends look quiet and a busy day can reflect a batch of advisories rather than more attacks. Select a bar to look at one day."+(base?" The line is the average of the prior "+base.n+" days; ▲ marks a day more than two standard deviations above it.":" A typical-day line appears once the map has seven days of history.")));
  v.appendChild(s1);
  /* 2. swimlanes */
  var lanes=viz.lane==="type"?CATS.map(function(c){return [c.k,c.label];}):viz.lane==="sector"?SECG:LAYERS.map(function(l){return [l[0],l[1]];});
  var keyOf=viz.lane==="type"?function(e){return e.category;}:viz.lane==="sector"?function(e){return e.secg;}:function(e){return e.layer;};
  var s2=el("div","vsec");s2.appendChild(el("h3",null,viz.lane==="layer"?"Which part of the environment is under pressure, and when?":viz.lane==="sector"?"Which sectors were hit, and when?":"What kind of events arrived, and when?"));
  s2.appendChild(el("p","q","Each mark is one event, in the column for its day. Bigger means more severe; hollow means an unverified claim; a blue ring means it matches your environment. The most important come first, and a +N chip opens the rest of a busy day. Select a mark to open the event."));
  var PITCH=19,MAXR=3,cols=Math.max(2,Math.floor((CW-12)/PITCH)),yy=22,geo=[];
  lanes.forEach(function(l){var evs=list.filter(function(e){return keyOf(e)===l[0];});if(!evs.length)return;
    var mxr=1;days.forEach(function(d){var n=evs.filter(function(e){return e.date===d;}).length;mxr=Math.max(mxr,Math.min(MAXR,Math.ceil(n/cols)));});
    var hgt=Math.max(40,mxr*PITCH+16);geo.push({l:l,evs:evs,y:yy,h:hgt});yy+=hgt+6;});
  var sw=d3.select(s2).append("svg").attr("viewBox","0 0 "+W0+" "+(yy+4));
  geo.forEach(function(g){sw.append("rect").attr("class","lane").attr("x",0).attr("y",g.y).attr("width",W0).attr("height",g.h).attr("rx",9);});
  days.forEach(function(d,i){
    sw.append("line").attr("class","gl").attr("x1",X(d)).attr("x2",X(d)).attr("y1",16).attr("y2",yy-2);
    if(d===today)sw.append("rect").attr("x",X(d)+1).attr("y",16).attr("width",CW-2).attr("height",yy-18).attr("rx",6).attr("fill","none").style("stroke","var(--accent)").style("stroke-width",1.5);
    sw.append("text").attr("class","ax").attr("x",X(d)+CW/2).attr("y",10).attr("text-anchor","middle").attr("font-weight",d===today?700:400).style("fill",d===today?"var(--accent)":null).text(d===today?"Today":parseDay(d).toLocaleDateString(undefined,{weekday:"short",day:"numeric"}));});
  geo.forEach(function(g){
    var hi=g.evs.filter(function(e){return e.severity>=3&&e.status!=="claimed";}).length,words=g.l[1].split(": ");
    var lt=sw.append("text").attr("class","lbl").attr("x",10).attr("y",g.y+g.h/2-2).text(fit(words[0],7,LW-18));lt.append("title").text(g.l[1]);
    sw.append("text").attr("class","sublbl").attr("x",10).attr("y",g.y+g.h/2+12).text(g.evs.length+(g.evs.length===1?" event":" events")+(hi?" · "+hi+" high":""));
    days.forEach(function(d){var c=g.evs.filter(function(e){return e.date===d;}).sort(function(a,b){return b.pri-a.pri;});if(!c.length)return;
      var cap=cols*MAXR,over=c.length>cap?c.length-(cap-1):0,show=over?c.slice(0,cap-1):c,slots=show.length+(over?1:0);
      var rowsN=Math.ceil(slots/cols),used=Math.min(cols,slots),x0=X(d)+(CW-used*PITCH)/2+PITCH/2,y0=g.y+(g.h-rowsN*PITCH)/2+PITCH/2;
      show.forEach(function(e,i){evGlyph(sw,e,x0+(i%cols)*PITCH,y0+Math.floor(i/cols)*PITCH,true);});
      if(over){var i2=show.length,mx=x0+(i2%cols)*PITCH,my=y0+Math.floor(i2/cols)*PITCH,lab=g.l[1].split(":")[0]+" · "+fmtDay(d);
        var mg=sw.append("g").attr("class","ev").attr("tabindex",0).attr("role","button").attr("aria-label",over+" more events, "+lab).attr("transform","translate("+mx+","+my+")");
        mg.append("rect").attr("x",-9).attr("y",-8).attr("width",PITCH+1).attr("height",16).attr("rx",8).attr("fill","var(--solid)").style("stroke","var(--muted)").style("stroke-width",1);
        mg.append("text").attr("x",.5).attr("y",3.5).attr("text-anchor","middle").attr("font-size",9.5).attr("font-weight",700).text("+"+over);
        var go=function(){pickSet(c.map(function(e){return e.id;}),lab);};
        mg.on("click",go).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();go();}})
          .on("pointerenter",function(ev){tipAt(ev,c.length+" events",lab+" · select to list them all");}).on("pointerleave",hideTip);}
    });
  });
  v.appendChild(s2);
  /* 3. patch clock */
  var s3=el("div","vsec");s3.appendChild(el("h3",null,"How long do we have to patch?"));
  s3.appendChild(el("p","q","Flaws that CISA confirms attackers are using, measured from today against the US federal deadline. Use the deadline as an upper limit for your own patching."));
  var openDl=kev.filter(function(k){var n=kevLeft(k);return n!==null&&n>=0;}).length,lateDl=kev.filter(function(k){var n=kevLeft(k);return n!==null&&n<0&&n>=-14;}).length;
  s3.appendChild(el("p",openDl||lateDl?null:"vnone",openDl||lateDl?openDl+(openDl===1?" known-exploited flaw has":" known-exploited flaws have")+" a federal deadline ahead and "+lateDl+" passed in the last two weeks. The full deadline chart, a calendar file and the fix steps are on the Vulnerabilities page.":"No known-exploited flaws with a deadline in the last two weeks or ahead."));
  var s3a=el("a","btn ghost sm","Open the deadline chart");s3a.href="vulnerabilities.html#known";s3.appendChild(s3a);
  s3.appendChild(el("p","cav","Source: CISA Known Exploited Vulnerabilities catalog. The deadline binds US federal agencies only."));
  v.appendChild(s3);
}
function vizCorr(v,list){
  var days=winDays(),W0=Math.max(560,v.clientWidth-36),LW=Math.min(260,Math.max(170,W0*.28)),CW=(W0-LW)/days.length,today=ymd(new Date());
  var X=function(d){return LW+days.indexOf(d)*CW;};
  var hd=el("div","vhead");hd.appendChild(el("h2",null,"Correlation"));v.appendChild(hd);
  if(!list.length){v.appendChild(el("p","vnone","No events match these filters."));return;}
  var byId={};list.forEach(function(e){byId[e.id]=e;});
  /* 0a. ripple effects */
  var sr=el("div","vsec");sr.appendChild(el("h3",null,"Ripple effects: if this is real, what follows?"));
  sr.appendChild(el("p","q","For the events with the widest reach, the analysis pass sets out the direct effect, what it can lead to downstream, and what to watch for. These are reasoned consequences, not reports that they have happened."));
  var rp=ripples?ripples.items.filter(function(r){return byId[r.id];}).slice(0,6):[];
  if(!rp.length)sr.appendChild(el("p","vnone",ripples?"None of the analysed events are in this view.":"The analysis pass has not written ripple effects yet."));
  else{var rw=el("div","rips");rp.forEach(function(r){var e=byId[r.id],c=el("div","rip"),rh=el("div","rh");
    var tb=el("button",null,e.title);tb.type="button";tb.addEventListener("click",function(){select(e.id,false);});rh.appendChild(tb);
    rh.appendChild(el("span","badge "+(r.basis==="stated"?"stated":"timing"),r.basis==="stated"?"Stated by sources":"Reasoned, not observed"));
    r.who.forEach(function(w){rh.appendChild(el("span","badge",w));});c.appendChild(rh);
    var cols=el("div","cols");[["Direct effect",r.direct],["Can lead to",r.downstream],["Watch for",r.watch]].forEach(function(x){var col=el("div","col");col.appendChild(el("h4",null,x[0]));var ul=el("ul");x[1].forEach(function(t){ul.appendChild(el("li",null,t));});col.appendChild(ul);cols.appendChild(col);});
    c.appendChild(cols);rw.appendChild(c);});sr.appendChild(rw);
    if(ripples.generated)sr.appendChild(el("p","cav","Written "+fmtTime(ripples.generated)+". Consequences marked as reasoned are inferences from how the affected technology is normally used."));}
  v.appendChild(sr);
  /* 0b. flow */
  var sf=el("div","vsec");sf.appendChild(el("h3",null,"From threat to target: where does each kind of threat land?"));
  sf.appendChild(el("p","q","Read left to right: the kind of threat, the part of the environment it touches, and the sector affected. A thicker band means more events. Select a band to list them."));
  var tagRank=tally(list.reduce(function(a,e){e.tags.forEach(function(t){a.push(t);});return a;},[]),function(t){return t;}).slice(0,6).map(function(x){return x[0];});
  var fe=list.filter(function(e){return e.layer!=="org"&&e.tags.some(function(t){return tagRank.indexOf(t)>=0;});}).map(function(e){return {e:e,a:tagRank.filter(function(t){return e.tags.indexOf(t)>=0;})[0],b:e.layer,c:e.secg};});
  if(fe.length<4)sf.appendChild(el("p","vnone","Too few tagged technical events in this view to draw a flow."));
  else{
    var FH=Math.max(190,Math.min(300,fe.length*7)),NW=10,PAD=7,cx=[LW*.62,W0*.52,W0-170],lname={};LAYERS.forEach(function(l){lname[l[0]]=l[1].split(":")[0];});var sname={};SECG.forEach(function(s){sname[s[0]]=s[1];});
    var colsN=[["a",function(k){return k;}],["b",function(k){return lname[k];}],["c",function(k){return sname[k];}]].map(function(cdef,ci){
      var m=tally(fe,function(x){return x[cdef[0]];}),tot=fe.length,avail=FH-PAD*(m.length-1),yy=24;
      return m.map(function(kv){var hgt=Math.max(3,avail*kv[1]/tot),n={k:kv[0],n:kv[1],y:yy,h:hgt,label:cdef[1](kv[0]),so:0,to:0,ci:ci};yy+=hgt+PAD;return n;});});
    var sf2=d3.select(sf).append("svg").attr("viewBox","0 0 "+W0+" "+(FH+34));
    ["Kind of threat","Part of the environment","Sector affected"].forEach(function(t,i){sf2.append("text").attr("class","colh").attr("x",cx[i]+(i===2?NW:0)).attr("y",12).attr("text-anchor",i===0?"end":i===2?"start":"middle").text(t);});
    [[0,1,"a","b"],[1,2,"b","c"]].forEach(function(pr){
      var src=colsN[pr[0]],dst=colsN[pr[1]],links=[];
      src.forEach(function(s){dst.forEach(function(d){var evs=fe.filter(function(x){return x[pr[2]]===s.k&&x[pr[3]]===d.k;});if(evs.length)links.push({s:s,d:d,evs:evs});});});
      links.forEach(function(l){var th=l.s.h*l.evs.length/l.s.n,th2=l.d.h*l.evs.length/l.d.n,y0=l.s.y+l.s.so,y1=l.d.y+l.d.to;l.s.so+=th;l.d.to+=th2;
        var x0=cx[pr[0]]+NW,x1=cx[pr[1]],mx2=(x0+x1)/2;
        var dd="M"+x0+","+y0+"C"+mx2+","+y0+" "+mx2+","+y1+" "+x1+","+y1+"L"+x1+","+(y1+th2)+"C"+mx2+","+(y1+th2)+" "+mx2+","+(y0+th)+" "+x0+","+(y0+th)+"Z";
        var lab=l.s.label+" → "+l.d.label,go=function(){pickSet(l.evs.map(function(x){return x.e.id;}),lab);};
        sf2.append("path").attr("class","rib").attr("d",dd).attr("tabindex",0).attr("role","button").attr("aria-label",lab+": "+l.evs.length+" events")
          .on("click",go).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();go();}})
          .on("pointerenter",function(ev){tipAt(ev,lab,l.evs.length+(l.evs.length===1?" event":" events"));}).on("pointerleave",hideTip);});
      src.forEach(function(s){s.so=0;});dst.forEach(function(d){d.to=0;});});
    colsN.forEach(function(col,ci){col.forEach(function(n){sf2.append("rect").attr("class","nd").attr("x",cx[ci]).attr("y",n.y).attr("width",NW).attr("height",n.h).attr("rx",3);
      if(n.h>=9||col.length<7)sf2.append("text").attr("class","ndl").attr("x",ci===0?cx[ci]-7:cx[ci]+NW+7).attr("y",n.y+n.h/2+4).attr("text-anchor",ci===0?"end":"start").text((ci===1?"":"")+n.label+" · "+n.n);});});
    sf.appendChild(el("p","cav","Based on "+fe.length+" technical events that carry one of the six most common threat tags; each event is counted once, under its most common tag. Policy, enforcement and business news is left out. Sector and environment are assigned from wording, so treat thin bands as anecdotes."));}
  v.appendChild(sf);
  /* 1. chains */
  var s0=el("div","vsec");s0.appendChild(el("h3",null,"Chains: what led to what?"));
  s0.appendChild(el("p","q","Sequences the analysis pass assembled from the stored events. A solid arrow is a link the sources state; dashed is inferred; dotted is timing only."));
  var pats=analysis?analysis.patterns.map(function(p){var steps=(p.chain.length>1?p.chain:p.ids).map(function(i){return byId[i];}).filter(Boolean);return {p:p,steps:p.chain.length>1?steps:steps.slice().sort(function(a,b){return a.t-b.t;})};}).filter(function(x){return x.steps.length>1;}).sort(function(a,b){return (b.p.kind==="stated")-(a.p.kind==="stated")||b.p.conf-a.p.conf||b.steps.length-a.steps.length;}).slice(0,6):[];
  if(!pats.length)s0.appendChild(el("p","vnone",analysis?"No chain in the current analysis has two or more of the events in this view.":"The analysis pass has not written any chains yet."));
  else{var cw=el("div","chains");pats.forEach(function(x){var p=x.p,c=el("div","chain");
    var ch=el("div","ch");ch.appendChild(el("b",null,p.title));ch.appendChild(el("span","badge "+p.kind,KIND[p.kind]));ch.appendChild(el("span","badge timing","confidence "+CONF[p.conf].toLowerCase()));
    var sb=el("button",null,"Show these "+x.steps.length+" in the feed");sb.type="button";sb.className="badge";sb.style.border="0";sb.addEventListener("click",function(){pickSet(x.steps.map(function(e){return e.id;}),"Chain: "+p.title);});ch.appendChild(sb);c.appendChild(ch);
    var fl=el("div","flow");x.steps.slice(0,7).forEach(function(e,i){
      if(i){var prev=x.steps[i-1],ed=p.edges.find(function(g){return (g.from===prev.id&&g.to===e.id)||(g.from===e.id&&g.to===prev.id);});
        var ar=el("div","arr "+(ed?ed.basis:p.chain.length>1?p.kind:"timing"));ar.appendChild(el("span",null,ed&&ed.rel?ed.rel:p.chain.length>1?"then":"later"));ar.appendChild(el("i"));fl.appendChild(ar);}
      var b=el("button","step");b.type="button";b.style.setProperty("--cc","var(--c-"+e.category+")");b.appendChild(el("small",null,fmtDay(e.date)+" · "+CAT[e.category].one));b.appendChild(document.createTextNode(e.title.length>74?e.title.slice(0,72)+"…":e.title));
      b.addEventListener("click",function(){select(e.id,false);});fl.appendChild(b);});
    if(x.steps.length>7)fl.appendChild(el("div","arr","+"+(x.steps.length-7)+" more"));
    c.appendChild(fl);if(p.caveat)c.appendChild(el("p","cav","Caveat: "+p.caveat));cw.appendChild(c);});s0.appendChild(cw);}
  v.appendChild(s0);
  /* 2. shared factors */
  var s1=el("div","vsec");s1.appendChild(el("h3",null,"Shared factors: what do separate events have in common?"));
  s1.appendChild(el("p","q","Each row is one concrete thing named in two or more events: the same actor, the same CVE, or the same product. Marks show when those events landed. Select a row label to list them."));
  var groups=new Map();
  function add(type,name,e){if(!name)return;var k=type+"|"+name.toLowerCase();var g=groups.get(k);if(!g){g={type:type,name:name,evs:[]};groups.set(k,g);}if(g.evs.indexOf(e)<0)g.evs.push(e);}
  list.forEach(function(e){if(e.actor&&!/^(unknown|unattributed|none|n\/a)/i.test(e.actor))add("Actor",e.actor.split(/[;(]/)[0].trim().slice(0,40),e);
    e.cves.forEach(function(c){add("CVE",c,e);});e.products.forEach(function(p){add("Product",p.slice(0,40),e);});});
  var rank={Actor:3,CVE:2,Product:1},seenSets={};
  var gs=Array.from(groups.values()).filter(function(g){return g.evs.length>1;}).map(function(g){g.orgs=new Set(g.evs.map(function(e){return e.org;})).size;g.sev=d3.sum(g.evs,function(e){return e.severity;});return g;})
    .sort(function(a,b){return b.evs.length-a.evs.length||rank[b.type]-rank[a.type]||b.sev-a.sev;})
    .filter(function(g){var k=g.evs.map(function(e){return e.id;}).sort().join(",");if(seenSets[k])return false;seenSets[k]=1;return true;}).slice(0,12);
  if(!gs.length)s1.appendChild(el("p","vnone","No actor, CVE or product is named in more than one event in this view."));
  else{var RH=30,sh=gs.length*RH+18,sg=d3.select(s1).append("svg").attr("viewBox","0 0 "+W0+" "+sh);
    days.forEach(function(d){if(d===today)sg.append("rect").attr("class","today").attr("x",X(d)).attr("y",14).attr("width",CW).attr("height",sh-14).attr("rx",6);
      sg.append("text").attr("class","ax").attr("x",X(d)+CW/2).attr("y",10).attr("text-anchor","middle").text(d===today?"Today":parseDay(d).toLocaleDateString(undefined,{weekday:"short",day:"numeric"}));});
    gs.forEach(function(g,i){var yy=16+i*RH,lab=g.type+": "+g.name;
      var hit=sg.append("g").attr("class","ev").attr("tabindex",0).attr("role","button").attr("aria-label",lab+", "+g.evs.length+" events");
      hit.append("rect").attr("class","lane").attr("x",0).attr("y",yy).attr("width",W0).attr("height",RH-4).attr("rx",8);
      hit.append("text").attr("class","lbl").attr("x",10).attr("y",yy+12).attr("font-size",11.5).text(lab.length>36?lab.slice(0,35)+"…":lab);
      hit.append("text").attr("class","sublbl").attr("x",10).attr("y",yy+23).text(g.evs.length+" events · "+g.orgs+(g.orgs===1?" organisation":" organisations"));
      var go=function(){pickSet(g.evs.map(function(e){return e.id;}),lab);};
      hit.on("click",go).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();go();}});
      days.forEach(function(d){var c=g.evs.filter(function(e){return e.date===d;});var x0=X(d)+CW/2-(c.length-1)*7.5;
        c.forEach(function(e,j){evGlyph(sg,e,x0+j*15,yy+(RH-4)/2,true);});});});
    s1.appendChild(el("p","cav","A shared factor is not proof of one campaign. Many unrelated attackers use the same flaw or product, and actor names come from the sources and can be wrong."));}
  v.appendChild(s1);
  /* 3. matrix */
  var s2=el("div","vsec"),mh=el("div","vhead");mh.appendChild(el("h3",null,"What is hitting where?"));
  mh.appendChild(seg([["layer","Attack surface"],["sector","Sector"]],viz.mat,"Matrix rows",function(k){viz.mat=k;render();}));s2.appendChild(mh);
  s2.appendChild(el("p","q","Rows are "+(viz.mat==="layer"?"parts of the environment":"sectors")+", columns are threat tags. Each cell counts events carrying both. Select a cell to list them."));
  var rowsDef=(viz.mat==="layer"?LAYERS.map(function(l){return [l[0],l[1].split(":")[0]];}):SECG),rk=viz.mat==="layer"?function(e){return e.layer;}:function(e){return e.secg;};
  var tagN=tally(list.reduce(function(a,e){e.tags.forEach(function(t){a.push({t:t});});return a;},[]),function(x){return x.t;}).slice(0,8).map(function(x){return x[0];});
  var rws=rowsDef.map(function(r){var evs=list.filter(function(e){return rk(e)===r[0]&&e.tags.length;});return {k:r[0],n:r[1],evs:evs};}).filter(function(r){return r.evs.length;});
  if(!tagN.length||!rws.length)s2.appendChild(el("p","vnone","Not enough tagged events in this view."));
  else{var N=list.filter(function(e){return e.tags.length;}).length,colT={};tagN.forEach(function(t){colT[t]=list.filter(function(e){return e.tags.indexOf(t)>=0;}).length;});
    var MW=Math.min(W0,LW+tagN.length*92),cw2=(MW-LW-44)/tagN.length,chh=30,mhh=rws.length*chh+64,hot=0,mxc=1;
    var cells=[];rws.forEach(function(r){tagN.forEach(function(t){var ids=r.evs.filter(function(e){return e.tags.indexOf(t)>=0;});var n=ids.length,lift=n?(n*N)/(r.evs.length*colT[t]):0;mxc=Math.max(mxc,n);cells.push({r:r,t:t,n:n,ids:ids,hot:n>=3&&lift>=1.5,lift:lift});});});
    var sm=d3.select(s2).append("svg").attr("viewBox","0 0 "+W0+" "+mhh);
    tagN.forEach(function(t,j){sm.append("text").attr("class","ax").attr("transform","translate("+(LW+j*cw2+cw2/2)+",52) rotate(-28)").attr("text-anchor","start").attr("font-size",11).style("fill","var(--ink)").text(t);});
    rws.forEach(function(r,i){var yy=60+i*chh;sm.append("text").attr("class","lbl").attr("x",10).attr("y",yy+chh/2+3).attr("font-size",11.5).text(r.n);
      sm.append("text").attr("class","ax").attr("x",LW+tagN.length*cw2+8).attr("y",yy+chh/2+3).text(r.evs.length);});
    cells.forEach(function(c){var i=rws.indexOf(c.r),j=tagN.indexOf(c.t),x=LW+j*cw2+2,yy=60+i*chh+2;if(c.hot)hot++;
      var g=sm.append("g");
      var rc=g.append("rect").attr("class","cell"+(c.hot?" hot":"")).attr("x",x).attr("y",yy).attr("width",cw2-4).attr("height",chh-4).attr("rx",6)
        .attr("fill",c.n?"color-mix(in srgb,var(--accent) "+Math.round(12+58*c.n/mxc)+"%,transparent)":"transparent");
      if(c.n){g.append("text").attr("class","cellt").attr("x",x+(cw2-4)/2).attr("y",yy+(chh-4)/2).text(c.n+(c.hot?" ▲":""));
        rc.attr("tabindex",0).attr("role","button").attr("aria-label",c.r.n+" and "+c.t+": "+c.n+" events");
        var go=function(){pickSet(c.ids.map(function(e){return e.id;}),c.r.n+" × "+c.t);};
        rc.on("click",go).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();go();}})
          .on("pointerenter",function(ev){tipAt(ev,c.r.n+" × "+c.t,c.n+" of "+c.r.evs.length+" events in this row"+(c.n>=3?" · "+c.lift.toFixed(1)+"× the rate expected by chance":" · too few to compare"));}).on("pointerleave",hideTip);}
      else rc.style("cursor","default");});
    s2.appendChild(el("p","cav","▲ and a dark outline mark a combination seen at least 1.5 times more often than its row and column totals alone would predict, counted only where there are 3 or more events. With "+N+" tagged events this is a pointer for where to look, not a statistical finding. Rows are assigned from product and tag wording, so some events sit in the wrong row."+(hot?"":" No combination clears that bar in this view.")));}
  v.appendChild(s2);
}

/* ---------- known-exploited feed ---------- */
function cleanKev(id,d){
  if(!d||typeof d!=="object")return null;var cve=str(d.cve,24)||str(id,24);if(!/^CVE-\d{4}-\d+$/.test(cve))return null;
  var added=str(d.added,10),due=str(d.due,10);if(!isDay(added))return null;
  var k={cve:cve,vendor:str(d.vendor,80),product:str(d.product,120),name:str(d.name,200),added:added,due:isDay(due)?due:"",ransom:d.ransomware===true,desc:str(d.desc,420),cvss:numIn(d.cvss,0,10),epss:numIn(d.epss,0,1)};
  k.hay=(k.cve+" | "+k.vendor+" | "+k.product+" | "+k.name).toLowerCase();return k;
}
function kevWl(k){return wlHit(k.hay);}
function kevLeft(k){return k.due?Math.round((parseDay(k.due).getTime()-parseDay(ymd(new Date())).getTime())/864e5):null;}
function kevDueText(n){return n===null?"":n<0?"federal deadline passed "+(-n)+(n===-1?" day":" days")+" ago":n===0?"federal deadline today":"federal deadline in "+n+(n===1?" day":" days");}
/* The Exploited tab is a short summary. The full list, deadline chart, calendar file and fix steps live on the Vulnerabilities page. */
function renderKev(){
  var p=$("kev");if(!p)return;
  var wk=ymd(daysAgo(7)),open=kev.filter(function(k){return k.added>=wk;}).length;
  $("kevBadge").textContent=open?String(open):"";
  if(p.hidden)return;
  if(state.tab!=="kev")return;
  var st=p.scrollTop;p.textContent="";
  if(!kev.length){p.appendChild(el("div","empty",loaded?"The known-exploited feed has not been written yet. The feeds task fills it on its next run.":"Loading"));return;}
  var hd=el("div","khead");hd.appendChild(el("b",null,String(kev.length)));hd.appendChild(document.createTextNode(" flaws added to CISA's known-exploited list in the last 45 days · "));
  hd.appendChild(el("b",null,String(open)));hd.appendChild(document.createTextNode(" this week"));
  var nw=kev.filter(kevWl).length;if(wl.terms.length){hd.appendChild(document.createTextNode(" · "));hd.appendChild(el("b",null,String(nw)));hd.appendChild(document.createTextNode(" match your environment"));}
  if(sweep&&sweep.last_kev_at)hd.appendChild(document.createTextNode(" · synced "+(ago(sweep.last_kev_at)||"")));
  p.appendChild(hd);
  var go=el("a","btn","Open the Vulnerabilities page");go.id="kevMore";go.href="vulnerabilities.html#known";
  go.title="Every exploited flaw ranked for patching, deadlines, calendar file, check and fix steps, and a database of all CVEs";p.appendChild(go);
  /* the next deadlines: soonest first; with none open, the most recently added */
  var today=ymd(new Date()),next=kev.filter(function(k){return k.due&&k.due>=today;}).sort(function(a,b){return a.due<b.due?-1:a.due>b.due?1:0;});
  var shown=next.length?next.slice(0,5):kev.slice().sort(function(a,b){return a.added<b.added?1:a.added>b.added?-1:0;}).slice(0,5);
  p.appendChild(el("p","khead",next.length?"Next patch deadlines ("+next.length+" open):":"No open deadlines. Most recently added:"));
  shown.forEach(function(k){
    var left=kevLeft(k),c=el("article","kcard");
    var id=el("div","kid");id.appendChild(el("span",null,k.cve));id.appendChild(el("span",null,"added "+fmtDay(k.added)));
    if(kevWl(k))id.appendChild(el("span","pill wl","Matches your environment"));
    if(k.ransom)id.appendChild(el("span","pill kev","Used by ransomware"));
    if(left!==null)id.appendChild(el("span","pill "+(left<0?"over":"due"),left<0?"Deadline passed":left===0?"Due today":"Due in "+left+"d"));
    c.appendChild(id);
    c.appendChild(el("div","kt",(k.vendor&&k.product&&k.product.toLowerCase().indexOf(k.vendor.toLowerCase())<0?k.vendor+" "+k.product:k.product||k.vendor)||k.name));
    var meta=[k.cvss!==null?"CVSS "+k.cvss.toFixed(1):"",k.epss!==null?"EPSS "+(k.epss*100>=10?Math.round(k.epss*100):(k.epss*100).toFixed(1))+"%":"",kevDueText(left)].filter(Boolean).join(" · ");
    if(meta)c.appendChild(el("p","khead",meta));
    var acts=el("div","acts"),a=el("a",null,"Check and fix steps");a.href="vulnerabilities.html#"+encodeURIComponent(k.cve);acts.appendChild(a);
    c.appendChild(acts);p.appendChild(c);
  });
  p.appendChild(el("p","khead","Source: CISA Known Exploited Vulnerabilities catalog. Deadlines bind US federal agencies only; treat them as a sensible upper limit. A flaw that is not listed here can still be exploited."));
  p.scrollTop=st;
}

/* ---------- desktop notifications for new matches (only while a CyberView tab is open; nothing is sent anywhere) ---------- */
var notifyOn=false,kevSeen=null;
function canNotify(){return typeof Notification!=="undefined";}
function notifySync(){var b=$("notifyBtn");if(!b)return;var on=notifyOn&&canNotify()&&Notification.permission==="granted";
  b.setAttribute("aria-pressed",on?"true":"false");b.textContent=on?"Notifications on (this device)":"Notify me on this device";}
function notifyToggle(){
  if(!canNotify()){toast("This browser cannot show notifications.");return;}
  if(notifyOn){notifyOn=false;lsSet("cwm.notify","0");notifySync();toast("Notifications off.");return;}
  Notification.requestPermission().then(function(p){
    notifyOn=p==="granted";lsSet("cwm.notify",notifyOn?"1":"0");notifySync();
    toast(notifyOn?"You will get a notification here when a new event or exploited flaw matches your environment, while CyberView is open in a tab.":"Notifications are blocked for this site in your browser settings.");
  });
}
function notifyNew(items){
  if(!notifyOn||!wl.terms.length||!canNotify()||Notification.permission!=="granted"||!items.length)return;
  var first=items[0],title=items.length===1?"CyberView: new match for your environment":"CyberView: "+items.length+" new matches for your environment",
    opt={body:items.slice(0,3).map(function(x){return x.t;}).join("\n").slice(0,300),tag:"cyberview-"+first.id,icon:"icon-512.png"};
  try{var n=new Notification(title,opt);n.onclick=function(){try{window.focus();}catch(x){}first.go();n.close();};}
  catch(x){try{if(navigator.serviceWorker)navigator.serviceWorker.ready.then(function(r){return r.showNotification(title,opt);}).catch(function(){});}catch(y){}}
}
function notifyEvents(added){
  notifyNew(added.filter(function(e){return e.wl&&e.severity>=2&&(state.claims||e.status!=="claimed");}).sort(function(a,b){return b.severity-a.severity;})
    .map(function(e){return {id:e.id,t:["","","Medium","High"][e.severity]+": "+e.title,go:function(){showEvent(e.id);}};}));
}
function notifyKev(){
  var ids=new Set(kev.map(function(k){return k.cve;}));
  if(kevSeen){notifyNew(kev.filter(function(k){return !kevSeen.has(k.cve)&&kevWl(k);}).map(function(k){return {id:k.cve,t:"Exploited: "+k.cve+" "+k.vendor+" "+k.product,go:function(){location.href="vulnerabilities.html#"+encodeURIComponent(k.cve);}};}));}
  kevSeen=ids;
}

/* ---------- shift handover ---------- */
function hoBuild(){
  var since=lsGet("cwm.ho")||"",list=base(),now=new Date(),L=[];
  var sev=["","Low","Med","High"],line=function(e){return "- ["+sev[e.severity]+"] "+e.title+" ("+fmtDay(e.date)+")"+(e.action&&!/^no action/i.test(e.action)?"\n    Do: "+e.action:"");};
  L.push("CYBERVIEW HANDOVER  "+now.toLocaleString(undefined,{weekday:"short",month:"short",day:"numeric",hour:"numeric",minute:"2-digit"}));
  L.push("Window: last "+state.win+" days (today and the "+(state.win-1)+" before)"+(isFiltered()?" (filters on: "+$("scopeText").textContent+")":"")+" · "+list.length+" events");
  var todo=list.filter(function(e){return urgent(e);}).sort(function(a,b){return b.pri-a.pri;});
  L.push("");L.push("TOP PRIORITY ("+todo.length+")");todo.slice(0,10).forEach(function(e){L.push(line(e));});if(todo.length>10)L.push("  …and "+(todo.length-10)+" more");if(!todo.length)L.push("- none");
  var dl=kev.filter(function(k){var n=kevLeft(k);return n!==null&&n<=7&&n>=-3;}).sort(function(a,b){return kevLeft(a)-kevLeft(b);});
  L.push("");L.push("PATCH DEADLINES, KNOWN-EXPLOITED ("+dl.length+")");dl.slice(0,12).forEach(function(k){L.push("- "+k.cve+"  "+[k.vendor,k.product].filter(Boolean).join(" ")+" — "+kevDueText(kevLeft(k))+(k.ransom?" · used by ransomware":""));});if(!dl.length)L.push("- none within 7 days");
  if(since){var nw=list.filter(function(e){return e.firstSeen&&e.firstSeen>since;}).sort(function(a,b){return b.pri-a.pri;});
    L.push("");L.push("NEW SINCE LAST HANDOVER ("+nw.length+", since "+fmtTime(since)+")");nw.slice(0,10).forEach(function(e){L.push(line(e));});if(nw.length>10)L.push("  …and "+(nw.length-10)+" more");if(!nw.length)L.push("- none");}
  var wlh=list.filter(function(e){return e.wl;});
  if(wl.terms.length){L.push("");L.push("MATCHES YOUR ENVIRONMENT ("+wlh.length+")");wlh.slice(0,8).forEach(function(e){L.push(line(e));});if(!wlh.length)L.push("- none");}
  L.push("");L.push("Unverified attacker claims are left out. Details and sources: "+location.href.split("#")[0]);
  return L.join("\n");
}
function showKeys(){toast("Keys: J/K next and previous · O open source · / search · 1 2 3 views · drag to turn the globe · L layers · W wall mode · R refresh · F full screen · Esc back");}
/* ---------- modal dialogs: backdrop, focus moved in and restored, Tab kept inside, Esc closes ---------- */
var modalOpen=null,modalReturn=null;
function modalShow(id,open,opener){
  var d=$(id);
  if(open){if(modalOpen&&modalOpen!==id)modalShow(modalOpen,false);modalReturn=opener||document.activeElement;modalOpen=id;d.hidden=false;$("backdrop").hidden=false;document.body.classList.add("modal-open");}
  else{d.hidden=true;if(modalOpen===id){modalOpen=null;$("backdrop").hidden=true;document.body.classList.remove("modal-open");if(modalReturn&&modalReturn.focus)try{modalReturn.focus();}catch(x){}modalReturn=null;}}
}
$("backdrop").addEventListener("click",function(){if(modalOpen==="wlDlg")wlToggle(false);else if(modalOpen==="hoDlg")hoToggle(false);});
document.addEventListener("keydown",function(ev){
  if(ev.key!=="Tab"||!modalOpen)return;
  var f=Array.prototype.filter.call($(modalOpen).querySelectorAll("button,textarea,input,select,a[href],[tabindex]"),function(x){return !x.disabled&&x.offsetParent!==null&&x.tabIndex>=0;});
  if(!f.length)return;var first=f[0],last=f[f.length-1];
  if(ev.shiftKey&&document.activeElement===first){ev.preventDefault();last.focus();}else if(!ev.shiftKey&&document.activeElement===last){ev.preventDefault();first.focus();}
},true);
function hoToggle(open){var d=$("hoDlg");modalShow("hoDlg",open,$("hoOpen"));$("hoOpen").setAttribute("aria-expanded",open?"true":"false");
  if(open){var s=lsGet("cwm.ho");$("hoNote").textContent=s?"Includes what is new since your last handover on "+fmtTime(s)+".":"First handover on this device. Later ones also list what is new since the previous one.";$("hoText").value=hoBuild();$("hoText").focus();$("hoText").scrollTop=0;}}
function drawMarks(){
  gMarks.selectAll("*").remove();
  safe("arcs",drawArcs);
  if(state.view!=="map")return;
  if(ctxOn.gdacs&&ctx.gdacs)ctx.gdacs.items.forEach(function(x){
    var p=proj(x.lng,x.lat);if(!p)return;var px=T.applyX(p[0]),py=T.applyY(p[1]);
    var g=gMarks.append("g").attr("class","haz "+x.level).attr("transform","translate("+px+","+py+")").attr("tabindex",0).attr("role","link").attr("aria-label",x.name+", "+x.level+" disaster alert (opens GDACS)");
    g.append("circle").attr("r",8);g.append("path").attr("d","M0,-4.2V1.2M0,3.4V3.6");
    var open=function(){var w=null;try{w=window.open(safeUrl(x.url),"_blank","noopener");}catch(z){}if(w)w.opener=null;};
    g.on("click",open).on("keydown",function(ev){if(ev.key==="Enter"){ev.preventDefault();open();}})
     .on("pointerenter",function(){tip(px,py,x.name,x.level+" disaster alert"+(x.country?" · "+x.country:"")+" · GDACS · context, not a cyber event");}).on("pointerleave",hideTip);
  });
  var cs=clusters(lastList),recent=ymd(daysAgo(1));
  var cp=curPattern();
  if(cp&&cp.chain.length>1&&!rp.on){
    var pts=cp.chain.map(function(id){var e=lastList.find(function(x){return x.id===id;});if(!e||e.lat===null)return null;var p=proj(e.lng,e.lat);return p?[T.applyX(p[0]),T.applyY(p[1])]:null;}).filter(Boolean);
    if(pts.length>1){gMarks.append("path").attr("class","chainline").attr("d",d3.line().curve(d3.curveCatmullRom.alpha(.6))(pts));
      pts.forEach(function(p,i){var g=gMarks.append("g").attr("class","stepn").attr("transform","translate("+(p[0]+13)+","+(p[1]-13)+")");g.append("circle").attr("r",8);g.append("text").text(i+1);});}
  }
  cs.forEach(function(c){
    var g=gMarks.append("g").attr("transform","translate("+c.x+","+c.y+")").attr("tabindex",0).attr("role","button");
    if(c.items.length===1){
      var e=c.items[0].e;
      g.attr("class","m"+(e.status==="claimed"?" hollow":"")).attr("aria-label",e.title);
      if(e.date>=recent&&e.severity>1)g.append("circle").attr("class","pulse").attr("r",9).attr("stroke","var(--c-"+e.category+")");
      if(state.sel===e.id||wall.focus===e.id)g.append("circle").attr("class","ring"+(wall.focus===e.id?" wallr":"")).attr("r",e.wl||e.actorPin||e.countryPin?18:15);
      if(coarse)g.append("circle").attr("class","hit").attr("r",20);
      rings(g,e,1);
      g.append("path").attr("d",symPath(e.category,[0,70,125,200][e.severity]))
        .attr("fill","var(--c-"+e.category+")").style("stroke",e.status==="claimed"?"var(--c-"+e.category+")":null);
      g.on("click",function(){select(e.id,false);}).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();select(e.id,false);}});
      g.on("pointerenter",function(ev){if(ev.pointerType==="touch")return;tip(c.x,c.y,e.title,fmtDay(e.date)+" · "+(e.place||e.country)+" · "+CONF[e.conf]+" confidence"+pinNote(e)+(e.wl?" · match your environment":""));}).on("pointerleave",hideTip);
    }else{
      var ids=c.items.map(function(p){return p.e.id;});
      var has=(state.sel&&ids.indexOf(state.sel)>=0)||(wall.on&&wall.focus&&ids.indexOf(wall.focus)>=0);
      g.attr("class","cl"+(has?" sel":"")).attr("aria-label",ids.length+" events here");
      var cr=9+Math.min(9,Math.sqrt(ids.length)*2.4),nw=c.items.filter(function(p){return p.e.wl;}).length;
      if(coarse)g.append("circle").attr("class","hit").attr("r",Math.max(22,cr+6));
      if(nw)g.append("circle").attr("class","wlr").attr("r",cr+3.5);
      g.append("circle").attr("r",cr);
      g.append("text").text(ids.length);
      var act=function(){openCluster(c);};
      g.on("click",act).on("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();act();}});
      g.on("pointerenter",function(){tip(c.x,c.y,ids.length+" events",c.items.slice(0,3).map(function(p){return p.e.org||p.e.title;}).join(", ")+(ids.length>3?" …":"")+(nw?" · "+nw+" match your environment":""));}).on("pointerleave",hideTip);
    }
  });
}
function tip(x,y,a,b){var t=$("tip");t.textContent="";t.appendChild(document.createTextNode(a));if(b)t.appendChild(el("small",null,b));
  var s=$("svg").getBoundingClientRect();
  t.style.left=Math.min(s.width-130,Math.max(130,x*(s.width/W)))+"px";t.style.top=Math.max(44,y*(s.height/H))+"px";t.style.display="block";}
function hideTip(){$("tip").style.display="none";}
function flyTo(bx,by,k){
  if(globe&&state.view==="map"){var ll=globeProj.invert&&globeProj.invert([bx,by]);
    if(ll&&isFinite(ll[0])&&isFinite(ll[1])){flyGlobe(ll[0],ll[1],reduced?0:600);var tk=d3.zoomIdentity.translate(FX*(1-k),FY*(1-k)).scale(k);(reduced?svg:svg.transition().duration(600)).call(zoom.transform,tk);return;}}
  var t=d3.zoomIdentity.translate(FX,FY).scale(k).translate(-bx,-by);
  (reduced?svg:svg.transition().duration(600)).call(zoom.transform,t);
}
function openCluster(c){
  hideTip();
  var spread=0,cx=0,cy=0;
  c.items.forEach(function(p){cx+=p.bx;cy+=p.by;});cx/=c.items.length;cy/=c.items.length;
  c.items.forEach(function(p){spread=Math.max(spread,Math.hypot(p.bx-cx,p.by-cy));});
  if(spread*MAXK<R||T.k>=MAXK*0.95||(!wide&&T.k>=6)){state.spot=c.items.map(function(p){return p.e.id;});state.sel=null;setTab("feed");render();
    if(!wide&&!wall.on)requestAnimationFrame(function(){var sc=$("scope");if(sc&&!sc.hidden)sc.scrollIntoView({block:"start"});});return;}
  flyTo(cx,cy,Math.min(MAXK,Math.max(T.k*2.5,R*1.4/spread)));
}
function select(id,fromFeed){
  var prev=state.sel;
  state.sel=id;
  var e=id&&events.find(function(x){return x.id===id;});
  if(e&&state.tab!=="feed"){state.tab="feed";["brief","feed","kev","pat","ins"].forEach(function(k){$("tab-"+k).setAttribute("aria-selected",k==="feed"?"true":"false");$(k).hidden=k!=="feed";});}
  try{var url=id?"#e="+encodeURIComponent(id):location.pathname+location.search;
    if(id&&!prev&&!wall.on&&!rp.on&&!popping){history.pushState({cvEvent:1},"",url);pushedEvent=true;}
    else if(!id&&prev&&pushedEvent){pushedEvent=false;history.back();}
    else history.replaceState(history.state,"",url);}catch(x){}
  document.body.classList.toggle("reading",!!(id&&e));
  render();
  if(state.view==="map"){
    if(e&&fromFeed&&e.lat!==null){if(globe)turnTo(e.lng,e.lat);var p=proj(e.lng,e.lat);
      if(p){if(!prev||!savedT)savedT=savedT||T;var sx=T.applyX(p[0]),sy=T.applyY(p[1]);
        var inside=Math.abs(sx-FX)<FW*.44&&Math.abs(sy-FY)<FH*.42;
        if(!inside||T.k<2.4)flyTo(p[0],p[1],Math.max(T.k,2.6));}}
    else if(!id&&prev&&savedT){var bt=savedT;savedT=null;(reduced?svg:svg.transition().duration(450)).call(zoom.transform,bt);}
  }
  if(!id)savedT=null;
  /* phones: the details sit below the globe. Bring them into view when an event opens, and go back to where the
     reader was in the list (or to the globe) when it closes. */
  if(!wide&&!wall.on){
    if(id&&e){if(!prev)winTop=window.scrollY;
      var toBar=function(){var bar=$("dbar");if(bar&&!bar.hidden&&state.sel===id)window.scrollTo(0,Math.max(0,bar.getBoundingClientRect().top+window.scrollY-8));};
      toBar();requestAnimationFrame(function(){toBar();requestAnimationFrame(toBar);});}
    else if(!id&&prev){var pc=$("card-"+prev);if(pc&&winTop>0)pc.scrollIntoView({block:"center"});else window.scrollTo(0,winTop);}
  }
}

/* ---------- globe stories: arcs, blast radius, campaign replay, wall mode ---------- */
/* how far a point faces the viewer (dot product with the view centre; below 0 it is behind the globe) */
function facing(lng,lat){proj(0,0);var l=lng*RAD,p=lat*RAD,cp=Math.cos(p);return cp*Math.cos(l)*cv[0]+cp*Math.sin(l)*cv[1]+Math.sin(p)*cv[2];}
/* a great-circle arc lifted off the surface; it shows over the horizon and is hidden only where the globe covers it */
function arcD(a,b){
  var A=[a.lng,a.lat],B=[b.lng,b.lat],dist=d3.geoDistance(A,B);if(!(dist>0.002))return "";
  var ip=d3.geoInterpolate(A,B),c=projection.translate(),R0=projection.scale(),lift=Math.min(.16,.03+dist*.07),n=Math.max(10,Math.round(dist*36)),d="",pen=false;
  for(var i=0;i<=n;i++){
    var t=i/n,g=ip(t),q=projection(g),h=1+lift*Math.sin(Math.PI*t);if(!q){pen=false;continue;}
    var dx=(q[0]-c[0])*h,dy=(q[1]-c[1])*h;
    if(facing(g[0],g[1])<0&&Math.hypot(dx,dy)<=R0){pen=false;continue;}
    d+=(pen?"L":"M")+T.applyX(c[0]+dx).toFixed(1)+","+T.applyY(c[1]+dy).toFixed(1);pen=true;
  }
  return d;
}
var arcOn={links:true,origins:true};
var ARC_DEFS={
  links:{label:"Stated links",what:"Arcs between events that a source says are connected: a breached supplier and the customers hit through it, one campaign, one flaw. Links that are only inferred or rest on timing are not drawn here (see Patterns)."},
  origins:{label:"Attributed origins",what:"Dashed arcs from where an actor is said to be based to its victim, drawn only when a government or the investigating firm made the attribution, and labelled with who said so. Attribution can be wrong or disputed."}
};
function edgeKey(a,b){return a<b?a+"|"+b:b+"|"+a;}
/* every arc among the events on screen; "stated" only: from the events' own links and the analysis job's stated edges */
function arcsFor(list){
  var on={},out=[],seen={};list.forEach(function(e){on[e.id]=e;});
  function add(a,b,rel,url,src){if(!a||!b||a===b||a.lat===null||b.lat===null)return;var k=edgeKey(a.id,b.id);if(seen[k])return;seen[k]=1;out.push({kind:"link",a:a,b:b,rel:rel,url:url,src:src});}
  if(arcOn.links){
    list.forEach(function(e){e.links.forEach(function(l){add(e,on[l.to],l.rel,l.url,"source");});});
    if(analysis)analysis.patterns.forEach(function(p){p.edges.forEach(function(x){if(x.basis==="stated")add(on[x.from],on[x.to],x.rel,"","analysis");});});
  }
  if(arcOn.origins)list.forEach(function(e){
    if(e.attr&&e.lat!==null&&!e.actorPin&&d3.geoDistance([e.attr.lng,e.attr.lat],[e.lng,e.lat])>0.02)
      out.push({kind:"origin",a:{id:"origin:"+e.id,lng:e.attr.lng,lat:e.attr.lat},b:e,rel:"attributed to "+e.attr.actor+" by "+e.attr.by,url:e.attr.url,attr:e.attr});
  });
  return out;
}
/* links touching one event, for its card: outgoing, incoming and analysis edges, all stated */
function linksOf(e){
  var by={},out=[],seen={};events.forEach(function(o){by[o.id]=o;});
  function add(o,rel,url,src){if(!o||o.id===e.id||!claimOk(o)||seen[o.id])return;seen[o.id]=1;out.push({e:o,rel:rel,url:url,src:src});}
  e.links.forEach(function(l){add(by[l.to],l.rel,l.url,"source");});
  events.forEach(function(o){o.links.forEach(function(l){if(l.to===e.id)add(o,l.rel,l.url,"source");});});
  if(analysis)analysis.patterns.forEach(function(p){p.edges.forEach(function(x){if(x.basis!=="stated")return;if(x.from===e.id)add(by[x.to],x.rel,"","analysis");else if(x.to===e.id)add(by[x.from],x.rel,"","analysis");});});
  return out.slice(0,12);
}
function arcLabel(x){
  if(x.kind==="origin")return ["Attributed: "+x.attr.actor,"by "+x.attr.by+" ("+(x.attr.byType==="government"?"government":"investigating firm")+") · said to operate from "+x.attr.origin+" · not a victim location"];
  return [(x.a.org||x.a.title)+" ↔ "+(x.b.org||x.b.title),x.rel+" · link stated by "+(x.src==="source"?"the event's source":"sources (analysis)")];
}
function drawArcs(){
  gArcs.selectAll("*").remove();
  if(state.view!=="map")return;
  if(rp.on){drawReplay();return;}
  var arcs=arcsFor(lastList),sel=state.sel||wall.focus;
  var hot=sel?arcs.filter(function(x){return x.b.id===sel||x.a.id===sel;}):[];
  arcs.forEach(function(x){
    var d=arcD(x.a,x.b);if(!d)return;var on=hot.indexOf(x)>=0;
    var p=gArcs.append("path").attr("class","arc "+x.kind+(on?" hot":hot.length?" dim":"")).attr("d",d);
    var lb=arcLabel(x);
    p.on("pointerenter",function(ev){tipAt(ev,lb[0],lb[1]);}).on("pointerleave",hideTip)
     .on("click",function(){if(!wall.on)select(x.b.id===sel&&x.a.id&&x.a.id.indexOf("origin:")!==0?x.a.id:x.b.id,true);});
    p.append("title").text(lb[0]+". "+lb[1]);
  });
  /* blast radius: the selected event's reach, sized by how many stated links it has */
  if(sel&&hot.length){
    var e=events.find(function(z){return z.id===sel;}),pt=e&&e.lat!==null?proj(e.lng,e.lat):null;
    if(pt){var n=hot.filter(function(x){return x.kind==="link";}).length,r=20+9*Math.sqrt(Math.max(1,n));
      var g=gArcs.append("g").attr("class","blast").attr("transform","translate("+T.applyX(pt[0])+","+T.applyY(pt[1])+")");
      g.append("circle").attr("r",r);g.append("circle").attr("class","b2").attr("r",r*.62);
      if(n)g.append("text").attr("y",-r-5).text(n+" linked event"+(n>1?"s":""));}
  }
}
/* turn the globe smoothly to a point (shortest way round) */
var flyT=null;
function flyGlobe(lng,lat,ms,done){
  stopSpin();if(flyT){flyT.stop();flyT=null;}
  var to=[-lng,Math.max(-70,Math.min(70,-lat))],from=rot.slice();to[0]=from[0]+(((to[0]-from[0])%360+540)%360-180);
  var fin=function(){if(done)done();};
  if(reduced||!ms){rot=to;globeProj.rotate(rot);repath(false);drawMarks();fin();return;}
  var ip=d3.interpolate(from,to);
  flyT=d3.timer(function(t){var k=Math.min(1,t/ms);rot=ip(d3.easeCubicInOut(k));globeProj.rotate(rot);frame();
    if(k>=1){flyT.stop();flyT=null;settle();fin();}});
}
function zoomHome(){svg.call(zoom.transform,d3.zoomIdentity);}

/* ---------- campaign replay: a pattern unfolds on the globe, one step at a time ---------- */
var rp={on:false,p:null,steps:[],i:0,timer:0};
var CISA_PT={lng:-77.09,lat:38.88};
function stageOf(e){
  var hay=(e.title+" "+e.summary).toLowerCase();
  if(e.category==="vuln"){if(/proof[- ]of[- ]concept|\bpoc\b|exploit code|public exploit|exploit released/.test(hay))return "Exploit published";
    if(e.kev||/actively exploited|exploited in the wild|under attack|zero-day/.test(hay))return "Exploited in the wild";return "Flaw disclosed";}
  if(e.category==="incident")return e.status==="claimed"?"Attacker claim (unverified)":"Victim hit";
  return {outage:"Outage",report:"Research published",policy:"Government responds",enforcement:"Regulator or police act",investment:"Market responds"}[e.category]||CAT[e.category].one;
}
function replaySteps(p){
  var by={};events.forEach(function(e){if(claimOk(e))by[e.id]=e;});
  var chain=p.chain.length>1,evs=(chain?p.chain:p.ids).map(function(i){return by[i];}).filter(Boolean);
  if(!chain)evs.sort(function(a,b){return a.t-b.t;});
  var steps=evs.map(function(e){return {e:e,id:e.id,lng:e.lng,lat:e.lat,t:e.t,date:e.date,stage:stageOf(e),title:e.title,where:whereOf(e)};});
  /* CISA's known-exploited listing of a CVE named in the pattern becomes its own step, at the agency */
  var cves={};evs.forEach(function(e){e.cves.forEach(function(c){cves[c]=1;});});
  kev.filter(function(k){return cves[k.cve];}).forEach(function(k){
    var s={e:null,id:"kev:"+k.cve,lng:CISA_PT.lng,lat:CISA_PT.lat,t:parseDay(k.added).getTime(),date:k.added,stage:"Listed as known exploited",
      title:"CISA adds "+k.cve+([k.vendor,k.product].filter(Boolean).length?" ("+[k.vendor,k.product].filter(Boolean).join(" ")+")":"")+" to its known-exploited catalog",where:"CISA, United States (agency location)",kev:k};
    var at=steps.findIndex(function(x){return x.t>s.t;});if(at<0)steps.push(s);else steps.splice(at,0,s);
  });
  return steps.slice(0,24);
}
function replayStart(id){
  var p=analysis&&analysis.patterns.find(function(x){return x.id===id;});if(!p)return;
  var steps=replaySteps(p);
  if(steps.filter(function(s){return s.lat!==null;}).length<2){toast("This pattern has fewer than two events with a map location, so there is nothing to replay.");return;}
  if(wall.on)wallStop();
  if(!$("layers").hidden)layersToggle(false);
  state.pattern=id;state.spot=null;state.day=null;state.sel=null;
  rp={on:true,p:p,steps:steps,i:0,timer:0};document.body.classList.add("replaying");
  if(state.view!=="map")setView("map");zoomHome();render();
  $("replay").hidden=false;if(!wide)window.scrollTo(0,0);replayGo(0);replayPlay(true);
  var f=$("rpPlay");if(f)f.focus();
}
function replayGo(i){
  if(!rp.on)return;rp.i=Math.max(0,Math.min(rp.steps.length-1,i));
  var s=rp.steps[rp.i];replayUi();
  if(s.lat!==null)flyGlobe(s.lng,s.lat,1400);else drawMarks();
}
function replayPlay(on){
  clearInterval(rp.timer);rp.timer=0;
  if(on){if(rp.i>=rp.steps.length-1)replayGo(0);rp.timer=setInterval(function(){if(document.hidden)return;if(rp.i>=rp.steps.length-1){replayPlay(false);return;}replayGo(rp.i+1);},reduced?6500:4800);}
  var b=$("rpPlay");if(b){b.textContent=on?"Pause":"Play";b.setAttribute("aria-pressed",on?"true":"false");}
}
function replayStop(){
  if(!rp.on)return;clearInterval(rp.timer);rp={on:false,p:null,steps:[],i:0,timer:0};
  document.body.classList.remove("replaying");$("replay").hidden=true;state.pattern=null;render();startSpin();
}
function replayUi(){
  var s=rp.steps[rp.i],n=rp.steps.length;
  $("rpTitle").textContent=rp.p.title;
  $("rpKind").textContent=KIND[rp.p.kind]+" · confidence "+CONF[rp.p.conf].toLowerCase();
  $("rpCount").textContent="Step "+(rp.i+1)+" of "+n;
  $("rpStage").textContent=s.stage;
  $("rpWhen").textContent=fmtDay(s.date)+(s.where?" · "+s.where:"")+(s.lat===null?" · no map location":"");
  var t=$("rpEvent");t.textContent=s.title;t.disabled=!s.e;
  var dots=$("rpDots");dots.textContent="";
  rp.steps.forEach(function(x,i){var b=el("button",i<rp.i?"done":i===rp.i?"cur":null);b.type="button";b.setAttribute("aria-label","Step "+(i+1)+": "+x.stage);b.title=(i+1)+". "+x.stage+" · "+fmtDay(x.date);
    b.addEventListener("click",function(){replayPlay(false);replayGo(i);});dots.appendChild(b);});
  $("rpPrev").disabled=rp.i===0;$("rpNext").disabled=rp.i===n-1;
  $("rpCav").textContent=rp.p.kind==="stated"?"Sources state these links. Dates are when each step was reported.":rp.p.kind==="timing"?"Timing only: these steps are close in time, which does not show they are connected.":"Inferred: the link is a judgement from shared attributes, not a reported fact.";
}
function drawReplay(){
  var pts=rp.steps.map(function(s){return s.lat===null?null:s;});
  var prev=null;
  for(var i=0;i<=rp.i;i++){var s=pts[i];if(!s)continue;
    if(prev){var d=arcD(prev,s);if(d)gArcs.append("path").attr("class","arc replay"+(i===rp.i?" hot":"")+(rp.p.kind==="stated"?"":" soft")).attr("d",d);}prev=s;}
  for(var j=0;j<=rp.i;j++){var st=pts[j];if(!st)continue;var p=proj(st.lng,st.lat);if(!p)continue;
    var x=T.applyX(p[0]),y=T.applyY(p[1]);
    if(j===rp.i){var g=gArcs.append("g").attr("class","rpcur").attr("transform","translate("+x+","+y+")");g.append("circle").attr("r",16);g.append("circle").attr("class","b2").attr("r",26);}
    if(!st.e){var a=gArcs.append("g").attr("class","agency").attr("transform","translate("+x+","+y+")");a.append("rect").attr("x",-6).attr("y",-6).attr("width",12).attr("height",12).attr("rx",2);}
    var b=gArcs.append("g").attr("class","stepn").attr("transform","translate("+(x+13)+","+(y-13)+")");b.append("circle").attr("r",8);b.append("text").text(j+1);}
}
$("rpPrev").addEventListener("click",function(){replayPlay(false);replayGo(rp.i-1);});
$("rpNext").addEventListener("click",function(){replayPlay(false);replayGo(rp.i+1);});
$("rpPlay").addEventListener("click",function(){replayPlay(!rp.timer);});
$("rpClose").addEventListener("click",replayStop);
$("rpEvent").addEventListener("click",function(){var s=rp.steps[rp.i];if(!s||!s.e)return;var id=s.e.id;replayStop();state.pattern=null;setTab("feed");select(id,true);});

/* ---------- wall mode: a hands-off display for a team's wall screen ---------- */
var wall={on:false,q:[],i:0,timer:0,tick:0,focus:null,lock:null,idle:0,seen:{}};
function wallQueue(){
  var cut=Date.now()-72*3600e3,old=ymd(daysAgo(2));
  return events.filter(function(e){return e.status!=="claimed"&&e.lat!==null&&(e.severity>=3||e.kev)&&((Date.parse(e.firstSeen)||0)>cut||e.date>=old);})
    .sort(function(a,b){return (Date.parse(b.firstSeen)||b.t)-(Date.parse(a.firstSeen)||a.t);}).slice(0,24);
}
function wallStart(){
  if(wall.on)return;
  if(rp.on)replayStop();if(modalOpen)modalShow(modalOpen,false);if(!$("layers").hidden)layersToggle(false);
  wall.on=true;document.body.classList.add("wall");$("wall").hidden=false;
  state.sel=null;state.spot=null;state.pattern=null;if(state.view!=="map")setView("map");
  try{history.replaceState(null,"",location.pathname+"?wall");}catch(x){}
  if(!fsOn())try{var r=document.documentElement,pr=(r.requestFullscreen||r.webkitRequestFullscreen).call(r);if(pr&&pr.catch)pr.catch(function(){});}catch(x){}
  try{if(navigator.wakeLock)navigator.wakeLock.request("screen").then(function(l){wall.lock=l;},function(){});}catch(x){}
  layout();zoomHome();render();
  wall.q=wallQueue();wall.i=0;wallNext();
  wall.timer=setInterval(function(){if(!document.hidden)wallNext();},15000);
  wall.tick=setInterval(wallClock,1000);wallClock();wallWake();
  $("wallExit").focus();
}
function wallStop(){
  if(!wall.on)return;wall.on=false;clearInterval(wall.timer);clearInterval(wall.tick);clearTimeout(wall.idle);
  document.body.classList.remove("wall","wall-idle");$("wall").hidden=true;wall.focus=null;
  try{if(wall.lock)wall.lock.release();}catch(x){}wall.lock=null;
  if(fsOn())try{(document.exitFullscreen||document.webkitExitFullscreen).call(document);}catch(x){}
  try{history.replaceState(null,"",location.pathname);}catch(x){}
  layout();render();resetGlobe();$("wallBtn").focus();
}
function wallNext(){
  if(!wall.q.length)wall.q=wallQueue();
  if(!wall.q.length){wall.focus=null;wallCaption(null);startSpin();return;}
  var e=wall.q[wall.i%wall.q.length];wall.i++;wall.focus=e.id;
  wallCaption(e);flyGlobe(e.lng,e.lat,2400);
}
/* new high-severity arrivals jump the queue and are shown at once */
function wallNew(added){
  if(!wall.on)return;var hot=added.filter(function(e){return e.status!=="claimed"&&e.lat!==null&&(e.severity>=3||e.kev);});
  wall.q=wallQueue();if(!hot.length)return;
  hot.forEach(function(e){wall.q=wall.q.filter(function(x){return x.id!==e.id;});wall.q.unshift(e);});
  wall.i=0;clearInterval(wall.timer);wallNext();wall.timer=setInterval(function(){if(!document.hidden)wallNext();},15000);
}
function wallCaption(e){
  var c=$("wCap");c.textContent="";
  if(!e){c.appendChild(el("p","wq","No new high-severity events in the last three days. Watching."));return;}
  var top=el("div","wtag");top.appendChild(glyph(e.category));top.appendChild(document.createTextNode(CAT[e.category].one+" · "+["","Low","Medium","High"][e.severity]+" severity"+(e.kev?" · known exploited":"")));c.appendChild(top);
  c.appendChild(el("h2",null,e.title));
  c.appendChild(el("p","wwhere",whereOf(e)+" · "+fmtWhen(e)+" · "+CONF[e.conf].toLowerCase()+" confidence"+pinNote(e)));
  if(e.action&&!/^no action/i.test(e.action))c.appendChild(el("p","wdo","Do: "+e.action));
}
function whereOf(e){return e.place&&e.country&&e.place.toLowerCase().indexOf(e.country.toLowerCase())>=0?e.place:[e.place,e.country].filter(function(x,i,a){return x&&a.indexOf(x)===i;}).join(", ");}
function wallClock(){
  var d=new Date();$("wClock").textContent=pad2(d.getUTCHours())+":"+pad2(d.getUTCMinutes())+":"+pad2(d.getUTCSeconds());
  $("wDate").textContent="UTC · "+d.toISOString().slice(0,10)+" · local "+DTF.clock.format(d);
  if(d.getSeconds()===0)wallStats();
}
function wallStats(){
  if(!wall.on)return;var box=$("wStats");box.textContent="";
  var today=new Date().toISOString().slice(0,10),cut=Date.now()-24*3600e3,ok=events.filter(function(e){return e.status!=="claimed";});
  var d24=ok.filter(function(e){return e.t>cut;});
  [[kev.filter(function(k){return k.added===today;}).length,"Known exploited","added today"],
   [kev.filter(function(k){return k.added>=ymd(daysAgo(7));}).length,"Known exploited","last 7 days"],
   [d24.filter(function(e){return e.severity>=3;}).length,"High severity","last 24 h"],
   [d24.length,"Events","last 24 h"],
   [new Set(d24.map(function(e){return normC(e.country);}).filter(Boolean)).size,"Countries","last 24 h"]].forEach(function(r){
    var s=el("div","wstat");s.appendChild(el("b",null,String(r[0])));s.appendChild(el("span",null,r[1]));s.appendChild(el("small",null,r[2]));box.appendChild(s);});
  var u=el("p","wupd","Data built "+(builtAt?ago(builtAt):"(loading)")+" · reloads every 5 min");box.appendChild(u);
  /* headline ticker: the newest confirmed events and known-exploited additions; doubled so the loop is seamless */
  var items=ok.slice().sort(function(a,b){return (Date.parse(b.firstSeen)||b.t)-(Date.parse(a.firstSeen)||a.t);}).slice(0,14).map(function(e){return [CAT[e.category].one,e.title,e.category];});
  kev.filter(function(k){return k.added>=ymd(daysAgo(2));}).slice(0,4).forEach(function(k){items.splice(1,0,["Known exploited",k.cve+" "+[k.vendor,k.product].filter(Boolean).join(" "),"vuln"]);});
  var key=items.map(function(x){return x[1];}).join("|");var tr=$("wTrack");if(tr.dataset.key===key)return;tr.dataset.key=key;tr.textContent="";
  [0,1].forEach(function(rep){items.forEach(function(x){var s=el("span","wit");if(rep)s.setAttribute("aria-hidden","true");s.style.setProperty("--cc","var(--c-"+x[2]+")");s.appendChild(el("b",null,x[0]));s.appendChild(document.createTextNode(x[1]));tr.appendChild(s);});});
  tr.style.animationDuration=Math.max(40,items.length*7)+"s";
}
function wallWake(){if(!wall.on)return;document.body.classList.remove("wall-idle");clearTimeout(wall.idle);wall.idle=setTimeout(function(){if(wall.on)document.body.classList.add("wall-idle");},3500);}
document.addEventListener("pointermove",wallWake,{passive:true});document.addEventListener("pointerdown",wallWake,{passive:true});
$("wallBtn").addEventListener("click",wallStart);
$("wallExit").addEventListener("click",wallStop);

/* ---------- render ---------- */
var faults={};
function safe(name,fn){
  try{fn();if(faults[name]){delete faults[name];fault();}}
  catch(x){if(!faults[name]){faults[name]=String(x&&x.message||x).slice(0,160);fault();try{console.error("CyberView: "+name+" failed",x);}catch(y){}}}
}
function fault(){var n=$("fault"),k=Object.keys(faults);if(!n)return;n.hidden=!k.length;n.textContent=k.length?"Part of this page could not be drawn ("+k.join(", ")+"). The rest is unaffected. Press Refresh; if it persists, use Report an error on any event.":"";}
function render(){
  var list=visible();lastList=list;
  if(state.sel&&!list.some(function(e){return e.id===state.sel;}))state.sel=null;
  safe("header",function(){renderStats(list);renderToggles();renderChips();renderDays();renderScope();});
  safe("brief",renderBrief);safe("feed",function(){if(state.tab==="feed")renderFeed(list);renderDetail(list);});safe("exploited",renderKev);safe("patterns",renderPatterns);safe("insights",function(){renderInsights(list);});
  safe("map",function(){if(state.view==="map"){shade();drawMarks();}else drawMarks();});
  if(state.view!=="map")safe("analysis",function(){renderViz(list);});
  safe("legend",renderKey);
  safe("wire",function(){wireBuild();hudTick();});
  if(wall.on)safe("wall",wallStats);
  lsSet("cwm.ui",JSON.stringify({win:state.win,sev:state.sev,sort:state.sort,lens:state.lens,view:state.view,cats:Array.from(state.cats)}));
}
function renderKey(){
  var k=$("key");k.textContent="";k.classList.toggle("shut",keyShut);
  var kt=el("button","kt",keyShut?"Legend":"Hide legend");kt.type="button";kt.setAttribute("aria-expanded",keyShut?"false":"true");
  kt.addEventListener("click",function(){keyShut=!keyShut;lsSet("cwm.key",keyShut?"1":"0");renderKey();});k.appendChild(kt);
  if(state.view==="graph"){[["stated","Link stated by sources"],["inferred","Inferred link"],["timing","Timing only"],["auto","Same actor or CVE"]].forEach(function(a){
    var s=el("span"),v=document.createElementNS(NS,"svg");v.setAttribute("viewBox","0 0 26 8");v.style.width="26px";v.style.height="8px";
    var l=document.createElementNS(NS,"line");l.setAttribute("class","edge "+a[0]);l.setAttribute("x1",1);l.setAttribute("x2",25);l.setAttribute("y1",4);l.setAttribute("y2",4);v.appendChild(l);s.appendChild(v);s.appendChild(document.createTextNode(a[1]));k.appendChild(s);});
    k.appendChild(el("span",null,"Circle = one pattern"));return;}
  var legendWl=function(){if(wl.terms.length)ringKey("wlr","Matches your environment");};
  function ringKey(cls,label){var s=el("span"),v=document.createElementNS(NS,"svg");v.setAttribute("viewBox","-8 -8 16 16");v.setAttribute("class","rg");v.setAttribute("aria-hidden","true");
    var c=document.createElementNS(NS,"circle");c.setAttribute("class",cls);c.setAttribute("r",6);v.appendChild(c);s.appendChild(v);s.appendChild(document.createTextNode(label));k.appendChild(s);}
  if(state.view==="time"){k.appendChild(el("span",null,"Exact position = reported time; others are placed on their day"));if(wl.terms.length)ringKey("wlr","Matches your environment");return;}
  var a=el("span");a.appendChild(glyph("incident"));a.appendChild(document.createTextNode("Confirmed"));k.appendChild(a);
  var b=el("span");b.appendChild(glyph("incident",true));b.appendChild(document.createTextNode("Unverified claim"));k.appendChild(b);
  if(!state.claims)b.lastChild.textContent="Unverified claim (hidden)";
  ringKey("act","Attributed origin, not a victim location");ringKey("ctry","Country-level location");legendWl();
  k.appendChild(el("span",null,"Bigger = more severe"));k.appendChild(el("span",null,"Shaded country = events there"));
}

/* ---------- data ---------- */
var rq=0;function renderSoon(){if(rq)return;rq=requestAnimationFrame(function(){rq=0;render();});}
function syncControls(){
  document.querySelectorAll("[data-win]").forEach(function(x){x.setAttribute("aria-pressed",+x.dataset.win===state.win?"true":"false");});
  document.querySelectorAll("[data-sev]").forEach(function(x){x.setAttribute("aria-pressed",+x.dataset.sev===state.sev?"true":"false");});
  $("q").value=state.q;$("status").value=state.status;$("sort").value=state.sort;$("lens").value=state.lens;
}
function loadPrefs(){
  keyShut=lsGet("cwm.key")!=="0";
  try{var ao=JSON.parse(lsGet("cwm.arcs")||"null");if(ao&&typeof ao==="object"){arcOn.links=ao.links!==false;arcOn.origins=ao.origins!==false;}}catch(x){}
  try{var o=JSON.parse(lsGet("cwm.ui")||"null");if(!o||typeof o!=="object")return;
    if(o.win===1)o.win=2;if([2,3,7].indexOf(o.win)>=0)state.win=o.win;if([1,2,3].indexOf(o.sev)>=0)state.sev=o.sev;
    if(["pri","new","sev","upd","rec","risk"].indexOf(o.sort)>=0)state.sort=o.sort;
    if(o.lens==="all"||own(LENS,o.lens))state.lens=o.lens;
    if(Array.isArray(o.cats)){var cs=o.cats.filter(function(c){return own(CAT,c);});if(cs.length)state.cats=new Set(cs);}
  }catch(x){}
}
function apply(snap){
  var before=new Set(events.map(function(e){return e.id;}));
  events=snap.docs.map(function(d){return clean(d.id,d.data());}).filter(Boolean);
  var added=loaded?events.filter(function(e){return !before.has(e.id);}):[];
  added.forEach(function(e){fresh.add(e.id);});
  if(added.length)setTimeout(function(){added.forEach(function(e){fresh.delete(e.id);});render();},90000);
  loaded=true;if(added.length){notifyEvents(added);wallNew(added);}return added.length;
}
function resetMain(){
  state.q="";state.status="all";state.lens="all";state.sev=1;state.win=7;state.sort="pri";state.wlOnly=false;state.claims=false;lsSet("cwm.claims","0");
  state.cats=new Set(CATS.map(function(c){return c.k;}));state.day=null;state.spot=null;state.country=null;state.pattern=null;state.sel=null;savedT=null;feedKey="";
  if(!$("wlDlg").hidden)wlToggle(false);if(!$("hoDlg").hidden)hoToggle(false);
  try{history.replaceState(null,"",location.pathname+location.search);}catch(x){}
  syncControls();setTab("feed");setView("map");resetGlobe();
  var f=$("feed");if(f)f.scrollTop=0;
}
function refresh(){
  var btn=$("refresh");
  resetMain();
  if(!db||!query){toast("Reset to the main view. The latest data can't be reached: check your connection and try again.");return;}
  if(btn.classList.contains("spin"))return;
  btn.classList.add("spin");
  var t0=Date.now();
  Promise.all([query.get(),db.doc("meta/status").get()]).then(function(r){
    var n=apply(r[0]);sweep=r[1].exists?r[1].data():sweep;stale=false;unavailable=false;
    render();
    toast("Refreshed and reset to the main view. "+(n?n+" new event"+(n>1?"s":"")+" loaded. ":"")+events.length+" events stored. Last sweep "+(sweep&&ago(sweep.last_sweep_at)||"unknown")+", next "+nextSweep()+".");
  }).catch(function(){toast("Reset to the main view, but the latest data could not be loaded. Check your connection and try again.");})
  .then(function(){setTimeout(function(){btn.classList.remove("spin");},Math.max(0,500-(Date.now()-t0)));});
}

/* ---------- controls ---------- */
document.querySelectorAll("[data-win]").forEach(function(b){
  b.addEventListener("click",function(){
    state.win=+b.dataset.win;state.day=null;state.spot=null;
    document.querySelectorAll("[data-win]").forEach(function(x){x.setAttribute("aria-pressed",x===b?"true":"false");});
    render();
  });
});
document.querySelectorAll("[data-sev]").forEach(function(b){
  b.addEventListener("click",function(){
    state.sev=+b.dataset.sev;
    document.querySelectorAll("[data-sev]").forEach(function(x){x.setAttribute("aria-pressed",x===b?"true":"false");});
    render();
  });
});
$("claims").addEventListener("click",function(){state.claims=!state.claims;lsSet("cwm.claims",state.claims?"1":"0");render();});
$("wlOnly").addEventListener("click",function(){state.wlOnly=!state.wlOnly;render();});
$("lens").addEventListener("change",function(ev){state.lens=own(LENS,ev.target.value)?ev.target.value:"all";render();});
function syncLevel(){document.querySelectorAll("[data-level]").forEach(function(x){x.setAttribute("aria-pressed",x.dataset.level===state.level?"true":"false");});}
document.querySelectorAll("[data-level]").forEach(function(b){
  b.addEventListener("click",function(){state.level=b.dataset.level;lsSet("cwm.level",state.level);syncLevel();render();});
});
function wlNote(){
  var n=events.filter(function(e){return e.wl&&inWindow(e)&&claimOk(e);}).length;
  var where=!wl.stored?"This list could not be stored and will be lost when you close the page.":"This list is saved on this device only.";
  $("wlNote").textContent=(wl.terms.length?wl.terms.length+" term"+(wl.terms.length>1?"s":"")+", "+n+" matching event"+(n===1?"":"s")+" in this window. ":"No terms yet. ")+where;
}
function wlToggle(open){
  modalShow("wlDlg",open,$("wlOpen"));$("wlOpen").setAttribute("aria-expanded",open?"true":"false");
  if(open){$("wlText").value=wl.terms.join("\n");$("envMsg").textContent="";envQuick();notifySync();wlNote();wlReport();wlDirty();wlTab("list");$("wlText").focus();}
}
function wlTab(t){
  var rep=t==="rep";$("wlTabList").setAttribute("aria-selected",rep?"false":"true");$("wlTabRep").setAttribute("aria-selected",rep?"true":"false");
  $("wlPaneList").hidden=rep;$("wlPaneRep").hidden=!rep;$("wlCopy").hidden=!rep||!wl.terms.length;$("wlSave").hidden=rep;$("wlRepEmpty").hidden=!!wl.terms.length;
  $("wlDlg").querySelector(".mbody").scrollTop=0;
}
function wlDirty(){
  var cur=wlParse($("wlText").value).join("\n"),dirty=cur!==wl.terms.join("\n");
  $("wlDirty").hidden=!dirty;$("wlCount").textContent=wl.terms.length?"("+wl.terms.length+")":"";
  var n=wl.terms.length?events.filter(function(e){return e.wl&&inWindow(e)&&claimOk(e);}).length+kev.filter(kevWl).length:0;$("wlHits").textContent=n?"("+n+")":"";
}
$("wlTabList").addEventListener("click",function(){wlTab("list");});
$("wlTabRep").addEventListener("click",function(){wlTab("rep");});
$("wlX").addEventListener("click",function(){wlToggle(false);});
$("wlTabList").addEventListener("keydown",function(ev){if(ev.key==="ArrowRight"){wlTab("rep");$("wlTabRep").focus();}});
$("wlTabRep").addEventListener("keydown",function(ev){if(ev.key==="ArrowLeft"){wlTab("list");$("wlTabList").focus();}});
/* ---------- environment import: the file is read here, in the browser, and never leaves the device ---------- */
var ENV_QUICK=["Microsoft","Windows","Exchange","Azure","Microsoft 365","Google Chrome","Apple","Linux","Cisco","Fortinet","Palo Alto Networks","Ivanti","Citrix","VMware","Atlassian","Oracle","SAP","AWS","Okta","CrowdStrike","SonicWall","Juniper","F5","WordPress","Apache","OpenSSL","Veeam","Zoom","Salesforce","GitHub"];
var ENV_STOP={"core":1,"common":1,"utils":1,"util":1,"test":1,"tests":1,"types":1,"lib":1,"api":1,"client":1,"server":1,"main":1,"app":1,"data":1,"config":1,"tools":1,"cli":1,"plugin":1,"plugins":1,"helpers":1,"base":1,"node":1,"none":1,"unknown":1,"n/a":1,"null":1,"true":1,"false":1,"name":1,"vendor":1,"product":1,"version":1,"software":1,"organization":1,"noassertion":1};
function envTerm(t){
  t=String(t==null?"":t).replace(/^(organization|person|tool):\s*/i,"").replace(/\s*\(.*?\)\s*$/,"")
    .replace(/[\s@]*v?\d+(\.\d+)+[\w.+-]*$/,"").replace(/^["'\s]+|["'\s]+$/g,"").replace(/\s+/g," ").trim();
  if(t.charAt(0)==="@")t=t.slice(1);
  var k=t.toLowerCase();
  if(t.length<3||t.length>60||/^[\d\W_]+$/.test(t)||ENV_STOP[k]||/^(https?:|[a-f0-9]{16,})/i.test(t))return "";
  return t;
}
function envCsvRows(text){
  var rows=[],row=[],f="",q=false;
  for(var i=0;i<text.length&&rows.length<5000;i++){var c=text.charAt(i);
    if(q){if(c==='"'){if(text.charAt(i+1)==='"'){f+='"';i++;}else q=false;}else f+=c;}
    else if(c==='"')q=true;else if(c===","||c===";"||c==="\t"){row.push(f);f="";}
    else if(c==="\n"||c==="\r"){if(c==="\r"&&text.charAt(i+1)==="\n")i++;row.push(f);rows.push(row);row=[];f="";}else f+=c;}
  if(f||row.length){row.push(f);rows.push(row);}
  return rows.filter(function(r){return r.some(function(x){return x.trim();});});
}
// returns {kind, terms}; kind names the format so the visitor can see what was understood
function envParse(name,text){
  var out=[],kind="text",push=function(v){var t=envTerm(v);if(t)out.push(t);};
  name=String(name||"").toLowerCase();text=String(text||"").replace(/^\uFEFF/,"").slice(0,2e6);
  var j=null;if(/^\s*[\[{]/.test(text)){try{j=JSON.parse(text);}catch(x){j=null;}}
  if(j&&typeof j==="object"){
    if(j.cyberview_environment&&Array.isArray(j.terms)){j.terms.forEach(function(t){if(typeof t==="string")out.push(t);});kind="CyberView profile";}
    else if(j.bomFormat==="CycloneDX"||Array.isArray(j.components)){kind="CycloneDX SBOM";
      (function walk(a,d){(Array.isArray(a)?a:[]).forEach(function(c){if(!c||typeof c!=="object"||d>6)return;
        push(c.publisher);push(c.supplier&&c.supplier.name);push(c.name);walk(c.components,d+1);});})(j.components,0);}
    else if(j.spdxVersion||Array.isArray(j.packages)){kind="SPDX SBOM";
      (j.packages||[]).forEach(function(p){if(p&&typeof p==="object"){push(p.supplier);push(p.originator);push(p.name);}});}
    else if(j.dependencies||j.devDependencies){kind="package.json";
      push(j.name);["dependencies","devDependencies","peerDependencies"].forEach(function(k){if(j[k]&&typeof j[k]==="object")Object.keys(j[k]).forEach(push);});}
    else if(Array.isArray(j)){kind="JSON list";j.forEach(function(x){if(typeof x==="string")push(x);else if(x&&typeof x==="object"){push(x.vendor||x.manufacturer||x.publisher);push(x.product||x.name||x.software);}});}
  }else if(/<bom[\s>]/i.test(text)){kind="CycloneDX SBOM (XML)";
    var re=/<(publisher|name)>([^<]{1,120})<\/\1>/gi,m,n=0;while((m=re.exec(text))&&n++<5000)push(m[2]);}
  else if(/\.(csv|tsv)$/.test(name)||/^[^\n]*[,;\t][^\n]*\n/.test(text)&&!/requirements|\.txt$/.test(name)){
    var rows=envCsvRows(text);kind="CSV";
    if(rows.length){var h=rows[0].map(function(x){return x.trim().toLowerCase();}),cols=[];
      h.forEach(function(x,i){if(/vendor|manufacturer|publisher|supplier|make\b/.test(x)||/product|software|application|^name$|display ?name|^title$|model|^os$|operating system|platform/.test(x))cols.push(i);});
      if(!cols.length)cols=[0];else rows=rows.slice(1);
      rows.forEach(function(r){cols.forEach(function(i){push(r[i]);});});}}
  else{kind=/requirements/.test(name)?"requirements.txt":"text list";
    text.split(/\n/).forEach(function(l){l=l.replace(/#.*/,"").trim();if(!l||/^-/.test(l))return;
      push(l.split(/\s*(?:==|>=|<=|~=|!=|>|<|;|\[)/)[0]);});}
  var seen={},terms=[];out.forEach(function(t){var k=t.toLowerCase();if(!seen[k]){seen[k]=1;terms.push(t);}});
  return {kind:kind,terms:terms};
}
function envMerge(add){
  var cur=wlParse($("wlText").value),have={};cur.forEach(function(t){have[t.toLowerCase()]=1;});
  var fresh=add.filter(function(t){return !have[t.toLowerCase()];}),room=Math.max(0,WL_MAX-cur.length);
  $("wlText").value=cur.concat(fresh.slice(0,room)).join("\n");envQuick();wlDirty();
  return {added:Math.min(fresh.length,room),skipped:Math.max(0,fresh.length-room)};
}
function envFile(f){
  if(!f)return;
  if(f.size>2e6){toast("That file is over 2 MB. Export just the software list, or paste the names.");return;}
  var r=new FileReader();
  r.onload=function(){
    var p=envParse(f.name,r.result);
    if(!p.terms.length){toast("Nothing usable found in "+String(f.name).slice(0,60)+". Try a CSV with vendor and product columns, an SBOM, or one name per line.");return;}
    var m=envMerge(p.terms);
    $("envMsg").textContent="Read "+String(f.name).slice(0,60)+" as "+p.kind+": "+p.terms.length+" names found, "+m.added+" added"+(m.skipped?", "+m.skipped+" left out (the list holds "+WL_MAX+")":"")+". Review the list, then Save. The file was read on this device and not uploaded.";
  };
  r.onerror=function(){toast("That file could not be read.");};
  r.readAsText(f);
}
function envQuick(){
  var box=$("envQuick");if(!box)return;box.textContent="";
  var have={};wlParse($("wlText").value).forEach(function(t){have[t.toLowerCase()]=1;});
  ENV_QUICK.forEach(function(t){var b=el("button","chip qk",t);b.type="button";b.setAttribute("aria-pressed",have[t.toLowerCase()]?"true":"false");
    b.addEventListener("click",function(){
      var cur=wlParse($("wlText").value);
      if(have[t.toLowerCase()])cur=cur.filter(function(x){return x.toLowerCase()!==t.toLowerCase();});else cur.push(t);
      $("wlText").value=cur.join("\n");envQuick();wlDirty();});
    box.appendChild(b);});
}
(function(){
  var dz=$("envDrop"),fi=$("envFile");
  $("envPick").addEventListener("click",function(){fi.click();});
  fi.addEventListener("change",function(){envFile(fi.files&&fi.files[0]);fi.value="";});
  ["dragenter","dragover"].forEach(function(t){dz.addEventListener(t,function(ev){ev.preventDefault();dz.classList.add("over");});});
  ["dragleave","drop"].forEach(function(t){dz.addEventListener(t,function(ev){ev.preventDefault();dz.classList.remove("over");});});
  dz.addEventListener("drop",function(ev){var f=ev.dataTransfer&&ev.dataTransfer.files&&ev.dataTransfer.files[0];envFile(f);});
  $("wlText").addEventListener("input",function(){clearTimeout(envQuick.t);envQuick.t=setTimeout(function(){envQuick();wlDirty();},200);});
  $("envExport").addEventListener("click",function(){
    var t=JSON.stringify({cyberview_environment:1,saved:new Date().toISOString().slice(0,10),terms:wlParse($("wlText").value)},null,1);
    try{navigator.clipboard.writeText(t).then(function(){toast("Profile copied. Save it as a .json file and drop it here on another device or for a colleague.");},function(){toast("Copy was blocked by the browser.");});}catch(x){toast("Copy was blocked by the browser.");}
  });
})();

/* ---------- exposure report: what in the watchlist is hit, worked out in the browser; nothing is sent ---------- */
var archRows=null,archLoad=null,xrText="";
function loadArchive(){
  if(!archLoad)archLoad=fetch("data/archive/search.json",{cache:"no-cache"}).then(function(r){if(!r.ok)throw new Error();return r.json();}).then(function(d){
    var f=Array.isArray(d.fields)?d.fields:[];archRows=(Array.isArray(d.rows)?d.rows:[]).map(function(r){var o={};f.forEach(function(k,i){o[k]=r[i];});
      o.hay=[o.title,o.org,o.country,o.actor,(o.cves||[]).join(" "),(o.tags||[]).join(" ")].join(" | ").toLowerCase();return o;});return archRows;
  }).catch(function(){archRows=[];return archRows;});
  return archLoad;
}
function wlReport(){
  var box=$("wlReport"),cp=$("wlCopy");box.textContent="";
  if(!wl.terms.length){box.hidden=true;cp.hidden=true;xrText="";return;}
  box.hidden=false;cp.hidden=$("wlPaneRep").hidden;
  var today=ymd(new Date()),lines=["CyberView exposure report, "+today,"Environment: "+wl.terms.join(", "),""];
  var kh=kev.filter(kevWl).sort(function(a,b){return (a.due||"9")<(b.due||"9")?-1:1;});
  var sec=el("section");sec.appendChild(el("h3",null,"Known-exploited flaws in your list ("+kh.length+")"));
  lines.push("Known-exploited flaws ("+kh.length+"):");
  if(!kh.length)sec.appendChild(el("p","xr-none","None in the last 45 days of CISA's catalog."));
  else{var ul=el("ul");kh.slice(0,12).forEach(function(k){
    var li=el("li"),over=k.due&&k.due<today;
    li.appendChild(document.createTextNode(k.cve+" · "+k.vendor+" "+k.product+" "));
    li.appendChild(el("span",over?"due over":"due",k.due?(over?"overdue since "+fmtDay(k.due):"patch by "+fmtDay(k.due)):""));
    if(k.ransom)li.appendChild(el("span","rw"," · used in ransomware"));
    ul.appendChild(li);lines.push("- "+k.cve+" "+k.vendor+" "+k.product+(k.due?(over?" OVERDUE since ":" patch by ")+k.due:"")+(k.ransom?" (ransomware)":""));
  });sec.appendChild(ul);}
  box.appendChild(sec);
  var eh=events.filter(function(e){return e.wl&&inWindow(e)&&claimOk(e);}).sort(function(a,b){return b.severity-a.severity||(a.date<b.date?1:-1);});
  sec=el("section");sec.appendChild(el("h3",null,"This window's events that mention it ("+eh.length+")"));
  lines.push("","Events in the last "+state.win+" days ("+eh.length+"):");
  if(!eh.length)sec.appendChild(el("p","xr-none","Nothing in the current window."));
  else{var ul2=el("ul");eh.slice(0,10).forEach(function(e){
    var li=el("li"),b=el("button",null,fmtDay(e.date)+" · "+["","Low","Medium","High"][e.severity]+" · "+e.title);b.type="button";
    b.addEventListener("click",function(){wlToggle(false);showEvent(e.id);});li.appendChild(b);ul2.appendChild(li);
    lines.push("- "+e.date+" ["+["","low","medium","high"][e.severity]+"] "+e.title+" "+eventLink(e.id));
  });if(eh.length>10)ul2.appendChild(el("li","xr-none","and "+(eh.length-10)+" more: turn on Only my environment."));sec.appendChild(ul2);}
  box.appendChild(sec);
  var as=el("section");as.appendChild(el("h3",null,"Across the whole archive"));var ap=el("p","xr-none","Counting");as.appendChild(ap);box.appendChild(as);
  xrText=lines.join("\n");
  var terms=wl.terms.slice();
  loadArchive().then(function(rows){
    if(terms.join("|")!==wl.terms.join("|"))return;
    ap.remove();var ul3=el("ul"),tot=0,arch=["","Across the whole archive:"];
    terms.forEach(function(t){var re=wlRe(t),n=rows.filter(function(r){return r.status!=="claimed"&&re.test(r.hay);}).length;if(!n)return;tot+=n;
      var li=el("li"),a=el("a",null,t+": "+n+" event"+(n===1?"":"s"));a.href="archive.html#q="+encodeURIComponent(t);li.appendChild(a);ul3.appendChild(li);arch.push("- "+t+": "+n);});
    if(!tot)as.appendChild(el("p","xr-none",rows.length?"No earlier events mention these terms.":"The archive could not be loaded."));else as.appendChild(ul3);
    xrText+= "\n"+arch.join("\n");
  });
}
function wlSave(){
  var terms=wlParse($("wlText").value),same=terms.join("\n")===wl.terms.join("\n");
  $("wlText").value=terms.join("\n");
  if(same){wlNote();wlDirty();if(terms.length)wlTab("rep");return;}
  wlApply(terms);if(!terms.length)state.wlOnly=false;render();wlReport();wlDirty();if(terms.length)wlTab("rep");
  var local=function(){wl.mode="local";wl.stored=lsSet("cwm.wl",JSON.stringify(terms));wlNote();toast(wl.stored?"Environment saved on this device only.":"Environment could not be stored. It will last until you close the page.");};
  local();
}
$("wlOpen").addEventListener("click",function(){wlToggle($("wlDlg").hidden);});
$("notifyBtn").addEventListener("click",notifyToggle);
notifyOn=lsGet("cwm.notify")==="1";
$("wlClose").addEventListener("click",function(){wlToggle(false);$("wlOpen").focus();});
$("wlSave").addEventListener("click",wlSave);
$("wlCopy").addEventListener("click",function(){
  try{navigator.clipboard.writeText(xrText).then(function(){toast("Exposure report copied.");},function(){toast("Copy was blocked by the browser.");});}catch(x){toast("Copy was blocked by the browser.");}
});
(function(){
  var lv=lsGet("cwm.level");if(lv==="plain"||lv==="standard"||lv==="exec")state.level=lv;
  state.claims=lsGet("cwm.claims")==="1";
  try{var t=JSON.parse(lsGet("cwm.wl")||"[]");wlApply(wlClean(t));}catch(x){}
  syncLevel();
})();
var qt=0;$("q").addEventListener("input",function(ev){var v=ev.target.value.trim();clearTimeout(qt);qt=setTimeout(function(){state.q=v;render();},140);});
$("status").addEventListener("change",function(ev){state.status=ev.target.value;render();});
$("sort").addEventListener("change",function(ev){state.sort=ev.target.value;render();});
$("scopeClear").addEventListener("click",function(){state.spot=null;state.country=null;state.day=null;state.pattern=null;
  state.q="";state.status="all";state.lens="all";state.sev=1;state.wlOnly=false;state.cats=new Set(CATS.map(function(c){return c.k;}));
  syncControls();render();});
$("dBack").addEventListener("click",function(){select(null);});
$("dPrev").addEventListener("click",function(){nav(-1);});
$("dNext").addEventListener("click",function(){nav(1);});
$("tab-feed").addEventListener("click",function(){setTab("feed");});
$("tab-brief").addEventListener("click",function(){setTab("brief");});
$("tab-ins").addEventListener("click",function(){setTab("ins");});
$("tab-pat").addEventListener("click",function(){setTab("pat");});
$("tab-kev").addEventListener("click",function(){setTab("kev");renderKev();});
$("hoOpen").addEventListener("click",function(){hoToggle($("hoDlg").hidden);});
$("hoClose").addEventListener("click",function(){hoToggle(false);$("hoOpen").focus();});
$("hoCopy").addEventListener("click",function(){var t=$("hoText").value,ok=function(){lsSet("cwm.ho",new Date().toISOString());toast("Handover copied. The next one will also list what is new from now.");hoToggle(false);},bad=function(){$("hoText").select();toast("Copy was blocked by the browser. The text is selected: copy it with your keyboard.");};
  try{navigator.clipboard.writeText(t).then(ok,bad);}catch(x){bad();}});
document.querySelectorAll("[data-view]").forEach(function(b){b.addEventListener("click",function(){setView(b.dataset.view);});});
function fsOn(){return !!(document.fullscreenElement||document.webkitFullscreenElement);}
function fsSync(){$("fs").setAttribute("aria-pressed",fsOn()?"true":"false");$("fsLabel").textContent=fsOn()?"Exit full screen":"Full screen";}
function toggleFs(){
  try{
    var d=document.documentElement,p;
    if(fsOn())p=(document.exitFullscreen||document.webkitExitFullscreen).call(document);
    else p=(d.requestFullscreen||d.webkitRequestFullscreen).call(d);
    if(p&&p.catch)p.catch(function(){toast("Full screen was blocked here. Open the map in its own tab and try again.");});
  }catch(x){toast("Full screen isn't available in this view. Open the map in its own tab and try again.");}
}
function themeSync(){var t=document.documentElement.dataset.theme==="dark"?"dark":"light";document.querySelectorAll("[data-theme-set]").forEach(function(x){x.setAttribute("aria-pressed",x.dataset.themeSet===t?"true":"false");});}
document.querySelectorAll("[data-theme-set]").forEach(function(b){b.addEventListener("click",function(){document.documentElement.dataset.theme=b.dataset.themeSet;lsSet("cwm.theme",b.dataset.themeSet);themeSync();render();});});
themeSync();
$("fs").addEventListener("click",toggleFs);
/* phones: the filter rows are folded away so the globe is on the first screen; this button opens them */
$("filtersDone").addEventListener("click",function(){document.body.classList.remove("filters-open");$("filtersBtn").setAttribute("aria-expanded","false");setTab("feed");setTimeout(function(){layout();render();var f=$("feed");if(f)f.scrollIntoView({block:"start"});},30);});
$("toFeed").addEventListener("click",function(){setTab("feed");var t=document.querySelector("aside .tabs");if(t)t.scrollIntoView({block:"start"});});
$("filtersBtn").addEventListener("click",function(){var on=!document.body.classList.contains("filters-open");document.body.classList.toggle("filters-open",on);$("filtersBtn").setAttribute("aria-expanded",on?"true":"false");setTimeout(function(){layout();render();},30);});
$("keysBtn").addEventListener("click",showKeys);
document.addEventListener("fullscreenchange",fsSync);document.addEventListener("webkitfullscreenchange",fsSync);
$("refresh").addEventListener("click",refresh);
$("zin").addEventListener("click",function(){svg.transition().duration(reduced?0:250).call(zoom.scaleBy,1.8);});
$("zout").addEventListener("click",function(){svg.transition().duration(reduced?0:250).call(zoom.scaleBy,1/1.8);});
$("zlayers").addEventListener("click",function(){layersToggle($("layers").hidden);});
$("zreset").addEventListener("click",function(){state.spot=null;state.country=null;svg.transition().duration(reduced?0:350).call(zoom.transform,d3.zoomIdentity);render();});
document.addEventListener("keydown",function(ev){
  var typing=/INPUT|SELECT|TEXTAREA/.test(document.activeElement&&document.activeElement.tagName);
  if(wall.on){if(ev.key==="Escape"||ev.key==="w"||ev.key==="W"){ev.preventDefault();wallStop();}else if(ev.key==="f"||ev.key==="F")toggleFs();else if(ev.key===" "||ev.key==="ArrowRight"){ev.preventDefault();wallNext();}return;}
  if(rp.on&&!typing){if(ev.key==="Escape"){replayStop();return;}if(ev.key==="ArrowRight"){ev.preventDefault();replayPlay(false);replayGo(rp.i+1);return;}if(ev.key==="ArrowLeft"){ev.preventDefault();replayPlay(false);replayGo(rp.i-1);return;}if(ev.key===" "&&document.activeElement===document.body){ev.preventDefault();replayPlay(!rp.timer);return;}}
  if(ev.key==="Escape"&&!$("wlDlg").hidden){wlToggle(false);$("wlOpen").focus();return;}
  if(ev.key==="Escape"&&!$("hoDlg").hidden){hoToggle(false);$("hoOpen").focus();return;}
  if(ev.key==="Escape"&&!$("layers").hidden){layersToggle(false);$("zlayers").focus();return;}
  if(ev.key==="Escape"){if(typing)document.activeElement.blur();else if(state.sel)select(null);else{state.spot=null;state.country=null;state.day=null;state.pattern=null;select(null);}}
  else if(typing||ev.metaKey||ev.ctrlKey||ev.altKey){}
  else if(ev.key==="j"||(ev.key==="ArrowDown"&&state.sel)){ev.preventDefault();nav(1);}
  else if(ev.key==="k"||(ev.key==="ArrowUp"&&state.sel)){ev.preventDefault();nav(-1);}
  else if(ev.key==="o"&&state.sel){openSource(events.find(function(z){return z.id===state.sel;}));}
  else if(ev.key==="1"||ev.key==="2"||ev.key==="3"){setView(["map","time","graph"][+ev.key-1]);}
  else if(ev.key==="?"){showKeys();}
  else if(!typing&&!ev.metaKey&&!ev.ctrlKey&&ev.key==="/"){ev.preventDefault();$("q").focus();}
  else if(!typing&&!ev.metaKey&&!ev.ctrlKey&&(ev.key==="r"||ev.key==="R")){refresh();}
  else if(!typing&&!ev.metaKey&&!ev.ctrlKey&&(ev.key==="f"||ev.key==="F")){toggleFs();}
  else if(!typing&&(ev.key==="l"||ev.key==="L")){layersToggle($("layers").hidden);}
  else if(!typing&&(ev.key==="w"||ev.key==="W")&&!modalOpen){wallStart();}
});
if(window.ResizeObserver){var rt=0;var rsz="";new ResizeObserver(function(){var r=$("stage").getBoundingClientRect(),k=Math.round(r.width)+"x"+Math.round(r.height)+"|"+(window.innerWidth>900);if(k===rsz)return;rsz=k;clearTimeout(rt);rt=setTimeout(function(){layout();render();},140);}).observe($("stage"));
  window.addEventListener("resize",function(){clearTimeout(rt);rt=setTimeout(function(){var k2=window.innerWidth+"x"+window.innerHeight;if(wide||k2.split("x")[0]!==String(lastW)){lastW=window.innerWidth;layout();render();}},160);});}
var lastW=window.innerWidth;
setInterval(function(){renderStats(lastList);if(state.tab==="ins")renderInsights(lastList);},60000);

window.addEventListener("error",function(ev){if(!faults.page){faults.page=String(ev&&ev.message||"error").slice(0,160);fault();}});
loadPrefs();syncControls();layout();setView(state.view);
fetch("world-110m.json").then(function(r){return r.json();}).then(function(topo){
  world=topojson.feature(topo,topo.objects.countries).features.filter(function(f){return f.id!=="010";});prepWorld();
  layout();drawMarks();startSpin();
}).catch(function(){/* outline missing: markers still plot on the graticule */});

// every URL that comes from data passes through here before it becomes a link
function safeUrl(u){u=String(u||"");return /^https?:\/\//i.test(u)?u:"about:blank";}
/* ---------- permalinks: #e=<id> opens one event (plain #<id> from older links still works) ---------- */
function hashId(){var h=location.hash.slice(1);try{h=decodeURIComponent(h);}catch(x){}if(h.indexOf("e=")===0)h=h.slice(2);return /^[a-z0-9][a-z0-9-]{2,119}$/.test(h)?h:"";}
function eventLink(id){return location.origin+location.pathname+"#e="+encodeURIComponent(id);}
function openFromHash(){
  var h=hashId();if(!h){if(state.sel)select(null);return;}
  if(h===state.sel)return;
  var he=events.find(function(e){return e.id===h;});
  if(!he){toast("That event is older than the map's window; opening it in the archive.");setTimeout(function(){location.href="archive.html#q="+encodeURIComponent(h);},900);return;}
  if(he.status==="claimed"&&!state.claims){state.claims=true;toast("This link points to an unverified claim, so claims are shown for now.");}
  state.day=null;state.spot=null;state.country=null;state.pattern=null;
  select(h,true);
}
window.addEventListener("hashchange",openFromHash);
/* opening an event adds one history entry, so the browser's Back button closes it (the phone's back gesture too) */
var pushedEvent=false,popping=false;
/* the page restores the reader's place itself (select()); the browser's own restore would fight it */
try{if("scrollRestoration" in history)history.scrollRestoration="manual";}catch(x){}
window.addEventListener("popstate",function(){pushedEvent=false;popping=true;try{openFromHash();}finally{popping=false;}});

/* ---------- data store: one static JSON bundle, re-read on a timer ---------- */
var STORE_URL="data/bundle.json",POLL_MS=5*60*1000;
// Error reports open a pre-filled GitHub issue (label event-report) that the verify and watchdog jobs read.
var REPORT_URL="https://github.com/xanderhutch/CyberView/issues/new";
function sendReport(p){
  var body="Event: "+p.title+"\nEvent id: "+p.event_id+"\nReported at: "+p.at+"\n\nWhat is wrong, and what should it say:\n"+p.note+"\n";
  var u=REPORT_URL+"?labels=event-report&title="+encodeURIComponent("Error report: "+String(p.title).slice(0,90))+"&body="+encodeURIComponent(body);
  var w=null;try{w=window.open(u,"_blank");if(w)w.opener=null;}catch(x){w=null;}
  return w?Promise.resolve():Promise.reject(new Error("popup blocked"));
}
function openStore(){
  var bundle=null,subs=[],last=null;
  function snapDocs(a){return {docs:a.map(function(r){return {id:r.id,data:function(){return r;}};}),size:a.length};}
  function docSnap(v){return {exists:!!v,data:function(){return v;}};}
  function rows(name){var a=bundle&&Array.isArray(bundle[name])?bundle[name]:[];return a.filter(function(r){return r&&typeof r==="object"&&typeof r.id==="string";});}
  function notify(){subs.forEach(function(f){try{f();}catch(x){}});}
  function load(){
    return fetch(STORE_URL,{cache:"no-cache"}).then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);return r.json();})
      .then(function(j){if(!j||typeof j!=="object"||!Array.isArray(j.events))throw new Error("bad bundle");var changed=j.built_at!==last;bundle=j;last=j.built_at;builtAt=str(j.built_at,30);return changed;});
  }
  function reload(){return load().then(function(ch){loadFailing=0;if(ch)notify();else renderSoon();},function(x){loadFailing++;renderSoon();throw x;});}
  function coll(name,filters,order,lim){
    function run(){
      var a=rows(name);
      filters.forEach(function(f){a=a.filter(function(r){var v=r[f[0]];return f[1]===">="?v>=f[2]:f[1]==="<="?v<=f[2]:v===f[2];});});
      if(order)a=a.slice().sort(function(x,y){var p=x[order[0]],q=y[order[0]];return (p<q?-1:p>q?1:0)*(order[1]==="desc"?-1:1);});
      return snapDocs(lim?a.slice(0,lim):a);
    }
    return {where:function(f,o,v){return coll(name,filters.concat([[f,o,v]]),order,lim);},orderBy:function(f,d){return coll(name,filters,[f,d||"asc"],lim);},limit:function(n){return coll(name,filters,order,n);},
      get:function(){return reload().then(run);},
      onSnapshot:function(cb){subs.push(function(){cb(run());});if(bundle)cb(run());return function(){};},
      add:function(payload){return name==="reports"?sendReport(payload):Promise.reject(new Error("read only"));}};
  }
  function doc(path){
    function val(){
      if(/^context\//.test(path)){var c=bundle&&bundle.context,k=path.slice(8);return c&&typeof c==="object"&&own(c,k)?c[k]:null;}
      return bundle&&bundle.docs&&own(bundle.docs,path)?bundle.docs[path]:null;}
    return {get:function(){return reload().then(function(){return docSnap(val());});},
      onSnapshot:function(cb){subs.push(function(){cb(docSnap(val()));});if(bundle)cb(docSnap(val()));return function(){};}};
  }
  setInterval(function(){if(!document.hidden)reload().catch(function(){});},POLL_MS);
  document.addEventListener("visibilitychange",function(){if(!document.hidden)reload().catch(function(){});});
  return load().then(function(){return {collection:function(n){return coll(n,[],null,0);},doc:doc};});
}
openStore().then(function(d){
  if(!d){unavailable=true;render();return;}
  db=d;query=db.collection("events").where("date",">=",ymd(daysAgo(9)));
  var timer=setTimeout(function(){if(!loaded){stale=true;render();}},10000),first=true;
  query.onSnapshot(function(snap){
    var n=apply(snap);
    if(!snap.metadata||!snap.metadata.fromCache){clearTimeout(timer);stale=false;}
    if(first){first=false;if(/[?&]wall(\b|=|&|$)/.test(location.search)){renderSoon();setTimeout(wallStart,60);return;}if(hashId()){openFromHash();return;}}
    else if(n)toast(n+" new event"+(n>1?"s":"")+" just arrived.");
    renderSoon();
  },function(){clearTimeout(timer);if(!loaded)unavailable=true;stale=false;render();});
  db.doc("analysis/latest").onSnapshot(function(s){analysis=s.exists?cleanAnalysis(s.data()):null;renderSoon();},function(){});
  try{db.collection("kev").where("added",">=",ymd(daysAgo(45))).onSnapshot(function(snap){kev=snap.docs.map(function(x){return cleanKev(x.id,x.data());}).filter(Boolean);notifyKev();renderKev();if(state.view!=="map")renderSoon();},function(){});}catch(x){}
  db.doc("analysis/ripples").onSnapshot(function(s){ripples=s.exists?cleanRipples(s.data()):null;if(state.view==="graph")renderSoon();},function(){});
  db.doc("wire/latest").onSnapshot(function(s){devWire=s.exists?cleanWire(s.data()):[];renderSoon();},function(){});
  db.doc("brief/latest").onSnapshot(function(s){daily=s.exists?cleanBrief(s.data()):null;renderBrief();},function(){});
  db.doc("stats/history").onSnapshot(function(s){hist=s.exists?cleanHist(s.data()):null;renderInsights(lastList);},function(){});
  try{db.collection("corrections").orderBy("at","desc").limit(20).onSnapshot(function(snap){
    corrections=snap.docs.map(function(x){return cleanCorr(x.data());}).filter(Boolean).slice(0,20);renderInsights(lastList);},function(){});}catch(x){}
  Object.keys(CTX_DEFS).forEach(function(k){db.doc("context/"+k).onSnapshot(function(s){ctx[k]=s.exists?cleanCtx(k,s.data()):null;renderLayers();if(state.view==="map")renderSoon();},function(){});});
  db.doc("meta/status").onSnapshot(function(s){sweep=s.exists?s.data():null;renderStats(lastList);if(state.tab==="ins")renderInsights(lastList);},function(){});
}).catch(function(){unavailable=true;render();});
})();
