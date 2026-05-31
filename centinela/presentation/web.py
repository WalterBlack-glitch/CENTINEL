"""Capa de presentación web: dashboard en vivo vía WebSocket + mapa geo.

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
<title>🛰 Centinela</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
:root{--bg:#0b0f17;--panel:#121826;--line:#1f2a3d;--txt:#cdd6e4;--dim:#6b7a91}
*{box-sizing:border-box}body{margin:0;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--txt)}
header{padding:10px 16px;background:#0d1320;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center}
header h1{font-size:15px;margin:0}#status{margin-left:auto;color:var(--dim)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#e5484d;margin-right:6px}
.dot.on{background:#30a46c}
.wrap{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);height:calc(100vh - 46px)}
.col{background:var(--bg);display:flex;flex-direction:column;min-height:0}
#map{height:46%;border-bottom:1px solid var(--line)}
.panel{flex:1;overflow:auto;padding:8px}
.panel h2{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin:4px 6px}
table{width:100%;border-collapse:collapse}td,th{padding:3px 6px;text-align:left;white-space:nowrap}
th{color:var(--dim);font-weight:600;position:sticky;top:0;background:var(--bg)}
tr{border-bottom:1px solid #131a28}
.sev0{color:var(--dim)}.sev1{color:#3aa6ff}.sev2{color:#f2c94c}.sev3{color:#ff6b6b}
.sev4{color:#fff;background:#7a1115}
.tag{color:var(--dim)}.alert td{font-weight:700}
.score{font-weight:700;text-align:right}
</style></head><body>
<header><h1>🛰 Centinela</h1><span class="tag" id="geoinfo"></span>
<span id="status"><span class="dot" id="dot"></span><span id="stxt">conectando…</span></span></header>
<div class="wrap">
  <div class="col">
    <div id="map"></div>
    <div class="panel"><h2>Eventos en vivo</h2>
      <table><thead><tr><th>hora</th><th>sev</th><th>fuente</th><th>tipo</th>
      <th>origen</th><th>geo</th><th>mensaje</th></tr></thead><tbody id="feed"></tbody></table>
    </div>
  </div>
  <div class="col"><div class="panel"><h2>Actores por score de amenaza</h2>
    <table><thead><tr><th>score</th><th>sev</th><th>IP</th><th>MAC</th>
    <th>fallos</th><th>users</th><th>puertos</th></tr></thead><tbody id="actors"></tbody></table>
  </div></div>
</div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>(s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const map=L.map('map',{worldCopyJump:true}).setView([20,0],2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
 {attribution:'© OpenStreetMap, © CARTO',subdomains:'abcd',maxZoom:7}).addTo(map);
const markers={};
function plot(ip,g,sev){if(!g)return;const k=ip;
 const color=['#6b7a91','#3aa6ff','#f2c94c','#ff6b6b','#ff2d2d'][sev]||'#6b7a91';
 if(markers[k]){markers[k].setStyle({color});return;}
 markers[k]=L.circleMarker([g.lat,g.lon],{radius:6,color,weight:2,fillOpacity:.5})
  .bindPopup(`<b>${esc(ip)}</b><br>${esc(g.city||'')} ${esc(g.country||'')}`).addTo(map);}
const tt=t=>new Date(t*1000).toLocaleTimeString();
function feedRow(e){const tb=$('#feed');const tr=document.createElement('tr');
 if(e.is_alert)tr.className='alert';
 let origin=esc(e.src_ip||'—');if(e.mac)origin+=' <span class="tag">mac='+esc(e.mac)+'</span>';
 if(e.vendor)origin+=' <span class="tag">('+esc(e.vendor)+')</span>';
 const geo=e.geo?esc((e.geo.country||'')+' '+(e.geo.city||'')):'<span class=tag>'+esc(e.scope||'')+'</span>';
 tr.innerHTML=`<td>${tt(e.ts)}</td><td class="sev${e.severity}">${e.sev_name}</td>
  <td>${esc(e.source)}</td><td>${esc(e.kind)}</td><td>${origin}</td><td>${geo}</td>
  <td>${esc(e.message)}</td>`;
 tb.prepend(tr);while(tb.children.length>120)tb.lastChild.remove();
 plot(e.src_ip,e.geo,e.severity);}
async function refreshActors(){try{const r=await fetch('/api/actors');const a=await r.json();
 $('#actors').innerHTML=a.map(x=>`<tr><td class="score sev${x.severity}">${x.score.toFixed(0)}</td>
  <td class="sev${x.severity}">${['INFO','LOW','MED','HIGH','CRIT'][x.severity]}</td>
  <td>${esc(x.ip)}</td><td>${esc(x.mac||'—')}</td><td>${x.fails}</td>
  <td>${x.users}</td><td>${x.ports}</td></tr>`).join('');}catch(e){}}
function connect(){const ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws');
 ws.onopen=()=>{$('#dot').className='dot on';$('#stxt').textContent='en vivo';};
 ws.onclose=()=>{$('#dot').className='dot';$('#stxt').textContent='reconectando…';setTimeout(connect,1500);};
 ws.onmessage=ev=>feedRow(JSON.parse(ev.data));}
connect();refreshActors();setInterval(refreshActors,2000);
</script></body></html>"""
