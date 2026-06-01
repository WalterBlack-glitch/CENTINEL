"""Capa de presentación web: dashboard SOC en vivo vía WebSocket + mapa geo.

FastAPI sirve una SPA de un solo archivo (HTML embebido) y un endpoint WebSocket
que retransmite cada ThreatEvent del bus en tiempo real. Si hay geolocalización
disponible (--geo), los actores se plotean en un mapa mundial (Leaflet, CDN).

Corre dentro del mismo event loop que el resto del pipeline (uvicorn.Server.
serve() como una task más), así comparte el EventBus sin IPC.

Dependencias (extra "web"): fastapi, uvicorn. Si no están, available()=False.
"""
from __future__ import annotations

import json

from ..core import EventBus, Severity
from ..correlation.engine import CorrelationEngine

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse
    import uvicorn
    _HAS_WEB = True
except Exception:
    _HAS_WEB = False


class WebDashboard:
    def __init__(self, bus: EventBus, engine: CorrelationEngine,
                 host: str = "127.0.0.1", port: int = 8787) -> None:
        self.bus = bus
        self.engine = engine
        self.host = host
        self.port = port

    @staticmethod
    def available() -> bool:
        return _HAS_WEB

    def _build_app(self):
        app = FastAPI(title="Centinela")

        @app.get("/", response_class=HTMLResponse)
        async def index():
            return _INDEX_HTML

        @app.get("/api/actors")
        async def actors():
            out = []
            for a in self.engine.get_actors()[:50]:
                out.append({
                    "ip": a.ip, "mac": a.last_mac, "score": a.score,
                    "fails": len(a.fails), "users": len(a.users),
                    "ports": len(a.ports),
                    "severity": int(self.engine._sev_from_score(a.score)),
                })
            return out

        @app.get("/api/clusters")
        async def clusters():
            # Adversarios atribuidos: IPs distintas agrupadas en un mismo actor.
            return [c.traits() for c in
                    self.engine.clusterer.get_clusters(min_ips=2)[:30]]

        @app.get("/api/stats")
        async def stats():
            actors = self.engine.get_actors()
            top = actors[0].score if actors else 0.0
            crit = sum(1 for a in actors
                       if self.engine._sev_from_score(a.score) >= Severity.HIGH)
            return {
                "actors": len(actors),
                "top_score": top,
                "high": crit,
                "dropped": self.bus.dropped,
                "clusters": len(self.engine.clusterer.get_clusters(min_ips=2)),
            }

        @app.websocket("/ws")
        async def ws(sock: WebSocket):
            await sock.accept()
            queue = self.bus.subscribe(maxsize=500)
            try:
                while True:
                    ev = await queue.get()
                    await sock.send_text(json.dumps(_event_payload(ev)))
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        return app

    async def run(self) -> None:
        if not _HAS_WEB:
            print("[centinela] capa web no disponible "
                  "(instala: pip install '.[web]')")
            return
        config = uvicorn.Config(self._build_app(), host=self.host,
                                port=self.port, log_level="warning",
                                access_log=False)
        server = uvicorn.Server(config)
        print(f"[centinela] dashboard web en http://{self.host}:{self.port}")
        await server.serve()


def _event_payload(ev) -> dict:
    geo = ev.enrichment.get("geo")
    return {
        "ts": ev.ts, "source": ev.source, "kind": ev.kind,
        "src_ip": ev.src_ip, "mac": ev.mac, "user": ev.user,
        "severity": int(ev.severity), "sev_name": Severity(ev.severity).name,
        "score": ev.score, "message": ev.message,
        "vendor": ev.enrichment.get("vendor"),
        "rdns": ev.enrichment.get("rdns"),
        "scope": ev.enrichment.get("scope"),
        "geo": geo,
        "is_alert": ev.kind.startswith("alert_"),
    }


_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Centinela · SOC</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
:root{
 --bg:#070b14; --bg2:#0a1120; --panel:rgba(18,26,44,.72); --glass:rgba(255,255,255,.04);
 --line:rgba(125,150,190,.14); --txt:#dce4f2; --dim:#76859e; --mut:#4a5870;
 --cyan:#22d3ee; --teal:#2dd4bf; --blue:#3b82f6;
 --s0:#5b6b82; --s1:#38bdf8; --s2:#fbbf24; --s3:#fb7185; --s4:#ff3b5c;
 --glow:0 0 0 1px var(--line), 0 8px 30px rgba(0,0,0,.45);
}
*{box-sizing:border-box;-webkit-font-smoothing:antialiased}
html,body{height:100%}
body{margin:0;font-family:Inter,system-ui,sans-serif;color:var(--txt);
 background:
  radial-gradient(1200px 600px at 80% -10%,rgba(34,211,238,.10),transparent 60%),
  radial-gradient(900px 500px at 0% 110%,rgba(59,130,246,.10),transparent 55%),
  linear-gradient(180deg,var(--bg),var(--bg2));
 background-attachment:fixed;overflow:hidden}
/* lluvia matrix de fondo */
#matrix{position:fixed;inset:0;width:100%;height:100%;z-index:0;opacity:.22;
 pointer-events:none;mix-blend-mode:screen}
header,.kpis,.grid{position:relative;z-index:1}
.mono{font-family:'JetBrains Mono',monospace}
/* header */
header{display:flex;align-items:center;gap:18px;padding:14px 22px;
 border-bottom:1px solid var(--line);background:rgba(7,11,20,.6);backdrop-filter:blur(8px)}
.brand{display:flex;align-items:center;gap:11px;font-weight:800;font-size:17px;letter-spacing:.2px}
.logo{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;
 background:linear-gradient(135deg,var(--cyan),var(--blue));box-shadow:0 0 18px rgba(34,211,238,.45);
 font-size:16px}
.brand small{color:var(--dim);font-weight:600;font-size:11px;letter-spacing:.16em;text-transform:uppercase}
.live{margin-left:auto;display:flex;align-items:center;gap:9px;font-size:12px;color:var(--dim);
 padding:7px 13px;border:1px solid var(--line);border-radius:999px;background:var(--glass)}
.dot{width:8px;height:8px;border-radius:50%;background:#e5484d;box-shadow:0 0 10px #e5484d}
.dot.on{background:#34d399;box-shadow:0 0 12px #34d399;animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
/* kpis */
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;padding:14px 22px}
.kpi{position:relative;padding:14px 16px;border-radius:14px;border:1px solid var(--line);
 background:linear-gradient(180deg,var(--glass),transparent);overflow:hidden}
.kpi::before{content:'';position:absolute;inset:0 auto 0 0;width:3px;background:var(--cyan);opacity:.8}
.kpi.k1::before{background:var(--blue)} .kpi.k2::before{background:var(--s2)}
.kpi.k3::before{background:var(--s3)} .kpi.k4::before{background:var(--s4)}
.kpi .lbl{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.12em;font-weight:600}
.kpi .val{font-size:30px;font-weight:800;line-height:1.1;margin-top:4px;font-family:'JetBrains Mono',monospace}
.kpi .sub{font-size:11px;color:var(--mut);margin-top:2px}
/* layout */
.grid{display:grid;grid-template-columns:1.35fr 1fr;gap:14px;padding:2px 22px 18px;
 height:calc(100vh - 64px - 92px)}
.card{display:flex;flex-direction:column;min-height:0;border-radius:16px;border:1px solid var(--line);
 background:var(--panel);box-shadow:var(--glow);overflow:hidden;backdrop-filter:blur(10px)}
.card>h2{margin:0;padding:12px 16px;font-size:12px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--dim);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px;font-weight:700}
.card>h2 .badge{margin-left:auto;font-size:11px;color:var(--cyan);background:rgba(34,211,238,.1);
 border:1px solid rgba(34,211,238,.25);border-radius:999px;padding:2px 9px}
.left{display:flex;flex-direction:column;gap:14px}
#map{height:54%;min-height:230px;border-radius:16px;border:1px solid var(--line);box-shadow:var(--glow);overflow:hidden}
.leaflet-container{background:#060a12}
.scroll{overflow:auto;flex:1}
.scroll::-webkit-scrollbar{width:8px}.scroll::-webkit-scrollbar-thumb{background:#1c2940;border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{position:sticky;top:0;background:rgba(10,17,32,.96);color:var(--dim);font-weight:600;
 text-align:left;padding:8px 14px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;z-index:1}
td{padding:7px 14px;border-bottom:1px solid rgba(125,150,190,.07);white-space:nowrap}
tr:hover td{background:rgba(255,255,255,.02)}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:10.5px;font-weight:700;
 letter-spacing:.04em;font-family:'JetBrains Mono',monospace}
.p0{color:var(--s0);background:rgba(91,107,130,.16)} .p1{color:var(--s1);background:rgba(56,189,248,.14)}
.p2{color:var(--s2);background:rgba(251,191,36,.14)} .p3{color:var(--s3);background:rgba(251,113,133,.16)}
.p4{color:#fff;background:linear-gradient(90deg,#ff3b5c,#b91c3c);box-shadow:0 0 14px rgba(255,59,92,.5)}
.ip{font-family:'JetBrains Mono',monospace;font-weight:600}
.tag{color:var(--mut);font-family:'JetBrains Mono',monospace;font-size:11px}
.feedrow{animation:slidein .35s ease}
@keyframes slidein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.alertrow td{background:linear-gradient(90deg,rgba(255,59,92,.10),transparent)!important;font-weight:600}
.flag{color:var(--s4);font-weight:800}
/* score bar */
.scorecell{display:flex;align-items:center;gap:8px;min-width:120px}
.bar{flex:1;height:6px;border-radius:6px;background:rgba(255,255,255,.06);overflow:hidden}
.bar>i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--teal),var(--cyan))}
.scoreval{font-family:'JetBrains Mono',monospace;font-weight:700;width:30px;text-align:right}
.geo{color:var(--dim)}
.cc{display:inline-block;min-width:22px;font-weight:700;color:var(--txt)}
.empty{padding:26px;text-align:center;color:var(--mut);font-size:13px}
/* clusters */
.cluster{margin:8px;padding:11px 13px;border-radius:12px;border:1px solid var(--line);
 background:linear-gradient(180deg,rgba(255,59,92,.06),transparent)}
.cluster .top{display:flex;align-items:center;gap:9px;margin-bottom:7px}
.cluster .cid{font-family:'JetBrains Mono',monospace;font-weight:800;color:var(--s4)}
.cluster .ipn{margin-left:auto;font-size:11px;color:#fff;background:linear-gradient(90deg,#ff3b5c,#b91c3c);
 padding:2px 10px;border-radius:999px;font-weight:700;box-shadow:0 0 12px rgba(255,59,92,.4)}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{font-family:'JetBrains Mono',monospace;font-size:10.5px;padding:2px 7px;border-radius:6px;
 background:rgba(255,255,255,.05);border:1px solid var(--line);color:var(--txt)}
.chip.u{color:var(--s2);background:rgba(251,191,36,.08)}
.cluster .lbl2{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.1em;margin:7px 0 4px}
@media(max-width:1000px){.kpis{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr;height:auto}}
</style></head><body>
<canvas id="matrix"></canvas>
<header>
 <div class="brand"><div class="logo">🛰</div>
  <div>Centinela<br><small>Threat Tracking · SOC</small></div></div>
 <div class="live"><span class="dot" id="dot"></span><span id="stxt">conectando…</span></div>
</header>

<section class="kpis">
 <div class="kpi"><div class="lbl">Eventos</div><div class="val mono" id="k_total">0</div><div class="sub" id="k_eps">0.0/s</div></div>
 <div class="kpi k1"><div class="lbl">Actores activos</div><div class="val mono" id="k_actors">0</div><div class="sub">IPs rastreadas</div></div>
 <div class="kpi k2"><div class="lbl">Amenaza máx.</div><div class="val mono" id="k_top">0</div><div class="sub">score más alto</div></div>
 <div class="kpi k3"><div class="lbl">Alertas</div><div class="val mono" id="k_alerts">0</div><div class="sub">en esta sesión</div></div>
 <div class="kpi k4"><div class="lbl">Críticos</div><div class="val mono" id="k_crit">0</div><div class="sub">HIGH / CRITICAL</div></div>
</section>

<div class="grid">
 <div class="left">
  <div id="map"></div>
  <div class="card" style="flex:1">
   <h2>📡 Eventos en vivo <span class="badge" id="b_feed">live</span></h2>
   <div class="scroll"><table><thead><tr>
     <th>hora</th><th>sev</th><th>fuente</th><th>tipo</th><th>origen</th><th>geo</th><th>detalle</th>
   </tr></thead><tbody id="feed"></tbody></table>
   <div class="empty" id="feed_empty">Esperando eventos…</div></div>
  </div>
 </div>
 <div class="left">
  <div class="card" style="flex:1.1">
   <h2>🎯 Actores por score de amenaza <span class="badge" id="b_actors">top 50</span></h2>
   <div class="scroll"><table><thead><tr>
     <th>score</th><th>sev</th><th>IP</th><th>MAC</th><th>fallos</th><th>users</th><th>puertos</th>
   </tr></thead><tbody id="actors"></tbody></table>
   <div class="empty" id="act_empty">Sin actores todavía.</div></div>
  </div>
  <div class="card" style="flex:1">
   <h2>🧬 Adversarios atribuidos <span class="badge" id="b_clusters">0</span></h2>
   <div class="scroll" id="clusters"></div>
   <div class="empty" id="cl_empty">Ninguna botnet atribuida aún. Cuando varias
    IPs compartan diccionario/TTPs se agruparán como un solo adversario.</div>
  </div>
 </div>
</div>

<script>
// --- lluvia "matrix" de fondo (canvas, sin dependencias) ---
(function(){
 const cv=document.getElementById('matrix'),cx=cv.getContext('2d');
 const glyphs='01<>{}[]/\\|=+*$#@%&·ｱｲｳｴｵｶｷｸｹｺﾊﾋﾌﾍﾎﾔﾕﾖ'.split('');
 let cols,drops,fs=14;
 function size(){cv.width=innerWidth;cv.height=innerHeight;
  cols=Math.floor(cv.width/fs);drops=Array(cols).fill(0).map(()=>Math.random()*-50);}
 size();addEventListener('resize',size);
 let last=0;
 function draw(t){
  if(t-last>55){last=t;
   cx.fillStyle='rgba(7,11,20,.10)';cx.fillRect(0,0,cv.width,cv.height);
   cx.font=fs+"px 'JetBrains Mono',monospace";
   for(let i=0;i<cols;i++){
    const ch=glyphs[(Math.random()*glyphs.length)|0],x=i*fs,y=drops[i]*fs;
    cx.fillStyle=Math.random()<0.04?'#aef9ff':'#22d3ee';
    cx.fillText(ch,x,y);
    if(y>cv.height&&Math.random()>0.975)drops[i]=0; else drops[i]++;}
  }
  requestAnimationFrame(draw);}
 requestAnimationFrame(draw);
})();
const $=s=>document.querySelector(s);
const esc=s=>(s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SEV=['INFO','LOW','MED','HIGH','CRIT'];
let total=0,alerts=0,crit=0,win=[];
// map
const map=L.map('map',{worldCopyJump:true,zoomControl:false,attributionControl:false}).setView([25,5],2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:8}).addTo(map);
const markers={};
function plot(ip,g,sev){if(!g||g.lat==null)return;
 const col=['#5b6b82','#38bdf8','#fbbf24','#fb7185','#ff3b5c'][sev]||'#5b6b82';
 if(markers[ip]){markers[ip].setStyle({color:col,fillColor:col});if(sev>=3)pulse(markers[ip]);return;}
 const m=L.circleMarker([g.lat,g.lon],{radius:6,color:col,fillColor:col,weight:2,fillOpacity:.55})
  .bindPopup(`<b>${esc(ip)}</b><br>${esc(g.city||'')} ${esc(g.country||'')}`);
 m.addTo(map);markers[ip]=m;if(sev>=3)pulse(m);}
function pulse(m){const el=m._path;if(!el)return;el.style.transition='none';el.setAttribute('r',12);
 el.style.opacity=.9;setTimeout(()=>{el.style.transition='all 1s';el.setAttribute('r',6);el.style.opacity=.55},30);}
const tt=t=>new Date(t*1000).toLocaleTimeString('es',{hour12:false});
function feedRow(e){
 total++;if(e.is_alert)alerts++;if(e.severity>=3)crit++;win.push(Date.now());
 $('#feed_empty').style.display='none';
 const tb=$('#feed'),tr=document.createElement('tr');
 tr.className='feedrow'+(e.is_alert?' alertrow':'');
 let origin='<span class="ip">'+esc(e.src_ip||'—')+'</span>';
 if(e.mac)origin+=' <span class="tag">'+esc(e.mac)+'</span>';
 if(e.vendor)origin+=' <span class="tag">'+esc(e.vendor)+'</span>';
 let geo=e.geo?('<span class="cc">'+esc(e.geo.country||'··')+'</span> <span class="geo">'+esc(e.geo.city||'')+'</span>')
   :'<span class="tag">'+esc(e.scope||'—')+'</span>';
 tr.innerHTML=`<td class="tag">${tt(e.ts)}</td>
  <td><span class="pill p${e.severity}">${e.sev_name}</span></td>
  <td class="tag">${esc(e.source)}</td><td>${esc(e.kind)}${e.is_alert?' <span class="flag">⚑</span>':''}</td>
  <td>${origin}</td><td>${geo}</td><td>${esc(e.message)}</td>`;
 tb.prepend(tr);while(tb.children.length>140)tb.lastChild.remove();
 plot(e.src_ip,e.geo,e.severity);
 $('#k_total').textContent=total;$('#k_alerts').textContent=alerts;$('#k_crit').textContent=crit;}
async function refresh(){
 try{const a=await (await fetch('/api/actors')).json();
  $('#act_empty').style.display=a.length?'none':'block';
  const mx=Math.max(100,...a.map(x=>x.score));
  $('#actors').innerHTML=a.map(x=>`<tr>
    <td><div class="scorecell"><span class="scoreval p${x.severity}" style="background:none">${x.score.toFixed(0)}</span>
     <div class="bar"><i style="width:${Math.min(100,x.score/mx*100)}%"></i></div></div></td>
    <td><span class="pill p${x.severity}">${SEV[x.severity]}</span></td>
    <td class="ip">${esc(x.ip)}</td><td class="tag">${esc(x.mac||'—')}</td>
    <td>${x.fails}</td><td>${x.users}</td><td>${x.ports}</td></tr>`).join('');
  const s=await (await fetch('/api/stats')).json();
  $('#k_actors').textContent=s.actors;$('#k_top').textContent=Math.round(s.top_score);
  // Adversarios atribuidos (botnets agrupadas en un solo actor)
  const cl=await (await fetch('/api/clusters')).json();
  $('#b_clusters').textContent=cl.length;
  $('#cl_empty').style.display=cl.length?'none':'block';
  $('#clusters').innerHTML=cl.map(c=>`<div class="cluster">
    <div class="top"><span class="cid">#${c.cid}</span>
      <span>adversario · score ${Math.round(c.score)}</span>
      <span class="ipn">${c.ip_count} IPs</span></div>
    <div class="lbl2">IPs del mismo actor</div>
    <div class="chips">${c.ips.slice(0,16).map(ip=>'<span class="chip">'+esc(ip)+'</span>').join('')}
      ${c.ip_count>16?'<span class="chip">+'+(c.ip_count-16)+'</span>':''}</div>
    <div class="lbl2">diccionario compartido</div>
    <div class="chips">${c.users.slice(0,12).map(u=>'<span class="chip u">'+esc(u)+'</span>').join('')}</div>
  </div>`).join('');
 }catch(e){}}
setInterval(()=>{const now=Date.now();win=win.filter(t=>now-t<3000);
 $('#k_eps').textContent=(win.length/3).toFixed(1)+'/s';},500);
function connect(){const ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws');
 ws.onopen=()=>{$('#dot').className='dot on';$('#stxt').textContent='EN VIVO';};
 ws.onclose=()=>{$('#dot').className='dot';$('#stxt').textContent='reconectando…';setTimeout(connect,1500);};
 ws.onmessage=ev=>feedRow(JSON.parse(ev.data));}
connect();refresh();setInterval(refresh,2000);
</script></body></html>"""
