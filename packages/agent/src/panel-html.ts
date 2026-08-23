import type { Lang } from "@tlk-sentinel/core";

const STR = {
  tr: {
    title: "tlk-sentinel",
    sub: "güvenlik paneli",
    live: "Canlı akış",
    total: "Tehdit (24s)",
    banned: "Banlanan",
    activeBans: "Aktif ban",
    dist: "Önem dağılımı",
    threats: "Son tehditler",
    bans: "Ban listesi",
    ip: "IP",
    rule: "Kural",
    sev: "Önem",
    when: "Zaman",
    country: "Ülke",
    action: "İşlem",
    unban: "Kaldır",
    empty: "kayıt yok",
    online: "bağlı",
    offline: "kopuk",
  },
  en: {
    title: "tlk-sentinel",
    sub: "security panel",
    live: "Live feed",
    total: "Threats (24h)",
    banned: "Banned",
    activeBans: "Active bans",
    dist: "Severity split",
    threats: "Recent threats",
    bans: "Ban list",
    ip: "IP",
    rule: "Rule",
    sev: "Severity",
    when: "Time",
    country: "Country",
    action: "Action",
    unban: "Remove",
    empty: "no records",
    online: "online",
    offline: "offline",
  },
};

const ICON = {
  shield:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.4-3 8.3-7 10-4-1.7-7-5.6-7-10V6z"/><path d="M9.5 12l1.8 1.8 3.2-3.6"/></svg>',
  alert:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9L2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>',
  ban:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>',
  lock:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></svg>',
  trash:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/><path d="M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12"/></svg>',
};

export function dashboardHtml(lang: Lang, tag: string): string {
  const s = STR[lang];
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${s.title} · ${s.sub}</title>
<style>
:root{
--bg:#080a0f;--bg2:#0d1017;--card:#11151d;--card2:#151a24;--line:#1e2733;--line2:#2a3543;
--fg:#e8eef6;--mut:#7d8b9e;--faint:#4a5666;
--crit:#ff5964;--high:#ff9f45;--med:#ffd43b;--low:#4da3ff;--ok:#3ddc97;
--accent:#5b8cff;--shadow:0 1px 0 rgba(255,255,255,.03),0 8px 24px rgba(0,0,0,.4);
--r:12px;--font:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#101826 0,var(--bg) 55%);color:var(--fg);font:13px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
svg{width:1em;height:1em;display:block}
header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:14px;padding:14px 22px;background:rgba(8,10,15,.82);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px}
.mark{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;color:#cfe0ff;background:linear-gradient(160deg,#1b2740,#0e1626);border:1px solid var(--line2);font-size:19px;box-shadow:var(--shadow)}
.brand h1{margin:0;font:600 15px/1 var(--sans);letter-spacing:.2px}
.brand span{color:var(--mut);font-size:11px;letter-spacing:.4px}
.spacer{flex:1}
.status{display:flex;align-items:center;gap:7px;color:var(--mut);font-size:12px;font-family:var(--font)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);transition:.3s}
.dot.on{background:var(--ok);box-shadow:0 0 0 4px rgba(61,220,151,.15)}
.tag{color:var(--faint);font-size:11px;font-family:var(--font);letter-spacing:.3px}
.wrap{padding:22px;max-width:1240px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:16px}
.stat{position:relative;background:linear-gradient(180deg,var(--card2),var(--card));border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;box-shadow:var(--shadow);overflow:hidden}
.stat .ico{position:absolute;right:14px;top:14px;color:var(--faint);font-size:20px;opacity:.7}
.stat .n{font:700 30px/1.1 var(--sans);letter-spacing:-.5px;font-variant-numeric:tabular-nums}
.stat .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.7px;margin-top:6px}
.stat.crit .n{color:var(--crit)}.stat.lock .ico{color:var(--high)}
.grid{display:grid;grid-template-columns:1.5fr .9fr;gap:16px}@media(max-width:880px){.grid{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);overflow:hidden;margin-bottom:16px}
.panel .h{display:flex;align-items:center;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line);color:var(--mut);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.7px}
.panel .h .c{margin-left:auto;color:var(--faint);font-family:var(--font)}
.feed{max-height:300px;overflow:auto;scrollbar-width:thin;scrollbar-color:var(--line2) transparent}
.fr{display:grid;grid-template-columns:64px 14px 1fr auto;align-items:center;gap:10px;padding:9px 16px;border-bottom:1px solid var(--line);animation:slide .35s ease}
.fr:last-child{border-bottom:0}
@keyframes slide{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.t{color:var(--faint);font-family:var(--font);font-size:11px}
.sd{width:8px;height:8px;border-radius:50%}
.fr .m{min-width:0;overflow:hidden}
.fr .m b{font-weight:600}.fr .m .sm{color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px}
.fr .ip{font-family:var(--font);color:var(--fg);font-size:12px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:9px 16px;border-bottom:1px solid var(--line);font-size:12.5px}
th{color:var(--faint);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tr:last-child td{border-bottom:0}tbody tr:hover{background:var(--bg2)}
.mono{font-family:var(--font)}.mut{color:var(--mut)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600;font-family:var(--font)}
.badge .sd{width:6px;height:6px}
.b-critical{background:rgba(255,89,100,.12);color:var(--crit)}
.b-high{background:rgba(255,159,69,.12);color:var(--high)}
.b-medium{background:rgba(255,212,59,.12);color:var(--med)}
.b-low,.b-info{background:rgba(77,163,255,.12);color:var(--low)}
.rm{display:inline-flex;align-items:center;gap:6px;background:var(--card2);color:var(--mut);border:1px solid var(--line2);border-radius:7px;padding:5px 10px;cursor:pointer;font:inherit;font-size:12px;transition:.15s}
.rm:hover{color:var(--crit);border-color:rgba(255,89,100,.4);background:rgba(255,89,100,.08)}
.dist{padding:14px 16px}
.bar{display:flex;align-items:center;gap:10px;margin:7px 0}
.bar .k{width:66px;color:var(--mut);font-size:11px;text-transform:capitalize}
.bar .track{display:block;flex:1;height:8px;background:var(--bg2);border-radius:6px;overflow:hidden}
.bar .fill{display:block;height:100%;min-width:2px;border-radius:6px;transition:width .5s ease}
.bar .v{width:34px;text-align:right;font-family:var(--font);color:var(--mut);font-size:11px}
.empty{padding:22px 16px;color:var(--faint);text-align:center;font-size:12px}
.bar.critical .fill{background:var(--crit)}
.bar.high .fill{background:var(--high)}
.bar.medium .fill{background:var(--med)}
.bar.low .fill,.bar.info .fill{background:var(--low)}
.bar .fill[style*="width:0%"]{background:var(--line2);min-width:0}
</style></head><body>
<header>
<div class="brand"><div class="mark">${ICON.shield}</div><div><h1>${s.title}</h1><span>${s.sub}</span></div></div>
<div class="spacer"></div>
<div class="status"><span class="dot" id="dot"></span><span id="conn">${s.offline}</span></div>
<span class="tag">${tag}</span>
</header>
<div class="wrap">
<div class="cards">
<div class="stat"><div class="ico">${ICON.alert}</div><div class="n" id="c-total">0</div><div class="l">${s.total}</div></div>
<div class="stat crit"><div class="ico">${ICON.ban}</div><div class="n" id="c-banned">0</div><div class="l">${s.banned}</div></div>
<div class="stat lock"><div class="ico">${ICON.lock}</div><div class="n" id="c-active">0</div><div class="l">${s.activeBans}</div></div>
</div>
<div class="panel"><div class="h">${s.live}<span class="c" id="feed-c">0</span></div><div class="feed" id="feed"><div class="empty">${s.empty}</div></div></div>
<div class="grid">
<div>
<div class="panel"><div class="h">${s.threats}</div><table><thead><tr><th>${s.when}</th><th>${s.sev}</th><th>${s.rule}</th><th>${s.ip}</th><th>${s.country}</th></tr></thead><tbody id="threats"></tbody></table></div>
</div>
<div>
<div class="panel"><div class="h">${s.dist}</div><div class="dist" id="dist"></div></div>
<div class="panel"><div class="h">${s.bans}<span class="c" id="bans-c">0</span></div><table><tbody id="bans"></tbody></table></div>
</div>
</div>
</div>
<script>
const L=${JSON.stringify(s)},SEV=["critical","high","medium","low","info"];
const qs=new URLSearchParams(location.search),tok=qs.get("token"),H=tok?{"x-panel-token":tok}:{};
const $=id=>document.getElementById(id),fmt=t=>new Date(t).toLocaleTimeString();
const SVAR={critical:"--crit",high:"--high",medium:"--med",low:"--low",info:"--low"};
const dotFor=x=>'<span class="sd" style="background:var('+(SVAR[x]||"--low")+')"></span>';
const badge=x=>'<span class="badge b-'+x+'">'+dotFor(x)+x+'</span>';
const esc=t=>String(t==null?"":t).replace(/[<>&]/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]));
async function j(u){const r=await fetch(u,{headers:H});if(!r.ok)throw 0;return r.json()}
let counters={total:0,banned:0,active:0},dirty=true;
function renderStats(d){counters={total:d.total,banned:d.banned,active:d.activeBans};paintCounters();renderDist(d.bySeverity||[])}
function paintCounters(){$("c-total").textContent=counters.total;$("c-banned").textContent=counters.banned;$("c-active").textContent=counters.active}
function renderDist(rows){const m={};let max=1;for(const r of rows){m[r.severity]=r.c;if(r.c>max)max=r.c}
 $("dist").innerHTML=SEV.map(k=>{const v=m[k]||0;return '<div class="bar '+k+'"><span class="k">'+k+'</span><span class="track"><span class="fill" style="width:'+(v/max*100)+'%"></span></span><span class="v">'+v+'</span></div>'}).join("")}
function renderThreats(d){$("threats").innerHTML=d.length?d.slice(0,60).map(t=>'<tr><td class="t mono">'+fmt(t.at)+'</td><td>'+badge(t.severity)+'</td><td class="mut">'+esc(t.rule)+'</td><td class="mono">'+esc(t.ip||"-")+'</td><td class="mut">'+esc(t.country||"")+'</td></tr>').join(""):'<tr><td colspan="5" class="empty">'+L.empty+'</td></tr>'}
function renderBans(d){$("bans-c").textContent=d.length;$("bans").innerHTML=d.length?d.map(b=>'<tr><td class="mono">'+esc(b.ip)+'</td><td class="mut">'+esc(b.rule)+'</td><td style="text-align:right"><button class="rm" data-ip="'+esc(b.ip)+'">${ICON.trash}'+L.unban+'</button></td></tr>').join(""):'<tr><td class="empty">'+L.empty+'</td></tr>'}
$("bans").addEventListener("click",async e=>{const btn=e.target.closest("button[data-ip]");if(!btn)return;btn.disabled=true;await fetch("api/unban",{method:"POST",headers:{...H,"content-type":"application/json"},body:JSON.stringify({ip:btn.getAttribute("data-ip")})});refresh(true)});
const feed=$("feed");let feedInit=false,feedN=0;
function pushFeed(t,banned){if(!feedInit){feed.innerHTML="";feedInit=true}
 const row=document.createElement("div");row.className="fr";
 row.innerHTML='<span class="t">'+fmt(t.at)+'</span>'+dotFor(t.severity)+'<span class="m"><b>'+esc(t.rule)+'</b> <span class="sm">'+esc(t.summary)+'</span></span><span class="ip">'+esc(t.ip||"-")+(banned?' '+badge("critical").replace(">critical<",">BAN<"):"")+'</span>';
 feed.prepend(row);feedN++;$("feed-c").textContent=feedN;
 while(feed.children.length>50)feed.lastChild.remove()}
async function refresh(force){try{const[st,th,bn]=await Promise.all([j("api/stats"),j("api/threats"),j("api/bans")]);renderStats(st);renderThreats(th);renderBans(bn);setConn(true)}catch{setConn(false)}}
function setConn(ok){$("dot").classList.toggle("on",ok);$("conn").textContent=ok?L.online:L.offline}
const es=new EventSource("api/stream"+(tok?"?token="+tok:""));
es.onopen=()=>setConn(true);es.onerror=()=>setConn(false);
es.onmessage=ev=>{const{threat,banned}=JSON.parse(ev.data);pushFeed(threat,banned);counters.total++;if(banned)counters.banned++;paintCounters();dirty=true};
refresh(true);setInterval(()=>{if(dirty){dirty=false;refresh()}},4000);
</script></body></html>`;
}
