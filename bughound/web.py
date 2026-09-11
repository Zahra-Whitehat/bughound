"""FastAPI web service and minimal dashboard for bughound."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .authorization import AuthorizationError, load_scope
from .engine import run_scan
from .models import ScanConfig
from .reporting import to_markdown

app = FastAPI(title="bughound", version="0.1.0")

# In-memory scan store: id -> {status, result, error, log}
SCANS: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    url: str
    authorized: bool = False
    authorize_hosts: list[str] = Field(default_factory=list)
    deny_hosts: list[str] = Field(default_factory=list)
    deny_urls: list[str] = Field(default_factory=list)
    aggressive: bool = False
    max_urls: int = 40
    max_depth: int = 2
    use_external_tools: bool = True


async def _run(scan_id: str, req: ScanRequest) -> None:
    entry = SCANS[scan_id]
    scope = load_scope(
        explicit_hosts=req.authorize_hosts,
        denied_hosts=req.deny_hosts,
        denied_urls=req.deny_urls,
    )
    config = ScanConfig(
        target_url=req.url,
        aggressive=req.aggressive,
        max_urls=req.max_urls,
        max_depth=req.max_depth,
        use_external_tools=req.use_external_tools,
    )

    def log(msg: str) -> None:
        entry["log"].append(msg)

    try:
        result = await run_scan(config, scope, confirmed=req.authorized, progress=log)
        entry["status"] = "done"
        entry["result"] = result
    except AuthorizationError as exc:
        entry["status"] = "unauthorized"
        entry["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001
        entry["status"] = "error"
        entry["error"] = f"{type(exc).__name__}: {exc}"


@app.post("/api/scan")
async def create_scan(req: ScanRequest) -> dict[str, str]:
    if not req.authorized:
        raise HTTPException(status_code=403, detail="Set authorized=true to confirm you may test this target.")
    scan_id = uuid.uuid4().hex[:12]
    SCANS[scan_id] = {"status": "running", "result": None, "error": None, "log": []}
    asyncio.create_task(_run(scan_id, req))
    return {"scan_id": scan_id, "status": "running"}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    entry = SCANS.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="unknown scan id")
    out: dict[str, Any] = {"status": entry["status"], "log": entry["log"], "error": entry["error"]}
    if entry["result"] is not None:
        out["result"] = entry["result"].model_dump(mode="json")
    return out


@app.get("/api/scan/{scan_id}/report.md", response_class=PlainTextResponse)
async def get_report(scan_id: str) -> str:
    entry = SCANS.get(scan_id)
    if not entry or entry["result"] is None:
        raise HTTPException(status_code=404, detail="report not ready")
    return to_markdown(entry["result"])


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return INDEX_HTML


INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>bughound</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#e6e6e6;background:#111}
 h1{color:#7ee787} label{display:block;margin:.6rem 0 .2rem} input,button{font-size:1rem;padding:.4rem}
 input[type=text]{width:100%;box-sizing:border-box;background:#1c1c1c;color:#eee;border:1px solid #333}
 .row{display:flex;gap:1rem;align-items:center;margin:.5rem 0}
 button{background:#238636;color:#fff;border:0;border-radius:6px;cursor:pointer}
 pre{background:#1c1c1c;padding:1rem;overflow:auto;border-radius:6px;white-space:pre-wrap}
 .warn{color:#f0883e;font-size:.9rem}
 table{border-collapse:collapse;width:100%} td,th{border:1px solid #333;padding:.3rem .5rem;text-align:left}
</style></head>
<body>
<h1>bughound</h1>
<p>Authorized web-vulnerability hunting agent. <span class="warn">Only scan systems you own or are explicitly permitted to test.</span></p>
<label>Target URL</label>
<input id="url" type="text" placeholder="https://example.com" />
<label>Authorized host(s) (comma-separated glob, e.g. *.example.com)</label>
<input id="hosts" type="text" placeholder="example.com" />
<label>Forbidden host(s) (comma-separated glob &mdash; never contacted)</label>
<input id="denyhosts" type="text" placeholder="admin.example.com, *.internal.example.com" />
<label>Forbidden URL(s) (comma-separated prefix &mdash; never contacted)</label>
<input id="denyurls" type="text" placeholder="https://example.com/logout" />
<div class="row"><label><input id="authorized" type="checkbox"/> I am authorized to test this target</label></div>
<div class="row"><label><input id="aggressive" type="checkbox"/> Aggressive (active exploitation)</label></div>
<button onclick="startScan()">Start scan</button>
<h3>Status</h3>
<pre id="status">idle</pre>
<div id="report"></div>
<script>
let timer=null;
async function startScan(){
  const csv=id=>document.getElementById(id).value.split(',').map(s=>s.trim()).filter(Boolean);
  const body={url:document.getElementById('url').value,
    authorize_hosts:csv('hosts'),
    deny_hosts:csv('denyhosts'),
    deny_urls:csv('denyurls'),
    authorized:document.getElementById('authorized').checked,
    aggressive:document.getElementById('aggressive').checked};
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  if(!r.ok){document.getElementById('status').textContent='Error: '+(j.detail||JSON.stringify(j));return;}
  poll(j.scan_id);
}
function poll(id){
  if(timer)clearInterval(timer);
  timer=setInterval(async()=>{
    const r=await fetch('/api/scan/'+id);const j=await r.json();
    document.getElementById('status').textContent=j.status+'\\n'+(j.error||'')+'\\n'+(j.log||[]).slice(-12).join('\\n');
    if(j.status==='done'){clearInterval(timer);render(id,j.result);}
    if(j.status==='error'||j.status==='unauthorized')clearInterval(timer);
  },1500);
}
function render(id,res){
  let rows=(res.findings||[]).sort((a,b)=>0).map(f=>`<tr><td>${f.severity}</td><td>${f.category}</td><td>${f.title}</td><td>${f.url}</td><td>${f.verified?'yes':f.confidence}</td></tr>`).join('');
  document.getElementById('report').innerHTML=`<h3>Findings (${(res.findings||[]).length})</h3>
   <table><tr><th>Sev</th><th>Class</th><th>Title</th><th>URL</th><th>Verified</th></tr>${rows}</table>
   <p><a style="color:#7ee787" href="/api/scan/${id}/report.md" target="_blank">Download Markdown report</a></p>`;
}
</script>
</body></html>
"""
