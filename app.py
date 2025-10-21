#!/usr/bin/env python3
"""
app.py - Flask app to upload Nmap XML or GNMAP and generate a polished HTML report.

Usage:
    pip install flask
    python3 app.py
Then open http://127.0.0.1:5000 in your browser.

Security notes:
- Allowed extensions: .xml, .gnmap
- Max upload size: 20 MB (configurable)
- Filenames sanitized with werkzeug.utils.secure_filename
- Uploaded files and generated reports are stored in 'uploads/' and 'reports/'
  with unique UUID-based filenames.
"""

import os
import uuid
import json
import html
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from flask import (
    Flask, request, render_template_string, redirect, url_for,
    send_from_directory, flash
)
from markupsafe import Markup
from werkzeug.utils import secure_filename

# ----------------- Configuration -----------------
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
ALLOWED_EXTENSIONS = {"xml", "gnmap"}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = os.urandom(24)  # for flash messages — in production set a stable secret

# ----------------- Utility & Parsers (robust) -----------------
def esc(s):
    return html.escape(str(s)) if s is not None else ""

def parse_nmap_xml(path):
    hosts = []
    try:
        tree = ET.parse(path)
    except Exception as e:
        raise RuntimeError(f"XML parse error: {e}")
    root = tree.getroot()
    for h in root.findall("host"):
        addr = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4","ipv6"):
                addr = a.get("addr")
        hostnames = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        os_el = h.find("os/osmatch")
        os_name = os_el.get("name") if os_el is not None else ""
        ports = []
        for p in h.findall("ports/port"):
            try:
                portid = int(p.get("portid"))
            except:
                continue
            proto = p.get("protocol") or ""
            st = p.find("state")
            state = st.get("state") if st is not None else "unknown"
            svc = p.find("service")
            service = svc.get("name") if svc is not None else ""
            prod = svc.get("product") if svc is not None else ""
            ver = svc.get("version") if svc is not None else ""
            ports.append({
                "port": portid,
                "proto": proto,
                "state": state,
                "service": service,
                "product": prod,
                "version": ver
            })
        hosts.append({
            "address": addr or "unknown",
            "hostnames": hostnames,
            "os": os_name,
            "ports": sorted(ports, key=lambda x: (x["port"], x["proto"]))
        })
    return hosts

def parse_gnmap(path):
    hosts = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if not line.startswith("Host:"):
                continue
            parts = line.split()
            addr = parts[1] if len(parts) > 1 else "unknown"
            try:
                ports_part = line.split("Ports:")[1].split("Ignored")[0]
            except:
                ports_part = ""
            ports = []
            for seg in [s.strip() for s in ports_part.split(",") if s.strip()]:
                bits = seg.split("/")
                if len(bits) < 3:
                    continue
                try:
                    portnum = int(bits[0])
                except:
                    continue
                state = bits[1] or "unknown"
                proto = bits[2] or ""
                svc = ""
                if len(bits) > 4 and bits[4]:
                    svc = bits[4]
                elif len(bits) > 3 and bits[3]:
                    svc = bits[3]
                ports.append({
                    "port": portnum,
                    "proto": proto,
                    "state": state,
                    "service": svc,
                    "product": "",
                    "version": ""
                })
            hosts.append({
                "address": addr,
                "hostnames": [],
                "os": "",
                "ports": sorted(ports, key=lambda x: x["port"])
            })
    return hosts

def load_input(path):
    low = path.lower()
    if low.endswith(".xml"):
        return parse_nmap_xml(path)
    if low.endswith(".gnmap"):
        return parse_gnmap(path)
    # Try simple autodetect
    with open(path, "rb") as fh:
        head = fh.read(400).lower()
        if b"<nmaprun" in head or b"<?xml" in head:
            return parse_nmap_xml(path)
    with open(path, "r", errors="ignore") as fh:
        sample = fh.read(2000)
        if "Ports:" in sample and "Host:" in sample:
            return parse_gnmap(path)
    raise ValueError("Unsupported file format. Upload an Nmap XML (-oX) or GNMAP (-oG) file.")

# ----------------- HTML report generator (uses placeholders) -----------------
def generate_html_report(hosts, title):
    # detect service substrings to show filters
    normalized_services = set()
    for h in hosts:
        for p in h["ports"]:
            if p.get("service"):
                normalized_services.add(p["service"].lower())

    candidate_filters = [
        ("http", "🌐"),
        ("ssh", "🔐"),
        ("ftp", "📦"),
        ("rdp", "🖥️"),
        ("mysql", "🛢️")
    ]
    filters_to_show = [(s, icon) for s, icon in candidate_filters if any(s in svc for svc in normalized_services)]

    data_js = json.dumps(hosts)

    # template plain string (no f-string to avoid JS {} conflicts)
    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>__TITLE__</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://unpkg.com/lucide@latest"></script>
<style>
body{background:#f9fafb;color:#0f172a;font-family:Inter,ui-sans-serif}
.card{background:white;border-radius:1rem;padding:1rem;box-shadow:0 4px 20px rgba(0,0,0,.05)}
.card:hover{box-shadow:0 6px 25px rgba(0,0,0,.07)}
.chip{border-radius:9999px;padding:.15rem .5rem;font-size:.75rem;font-weight:600;display:inline-block}
.chip-open{background:#dcfce7;color:#166534}
.chip-closed{background:#f3f4f6;color:#374151}
.chip-filtered{background:#fef9c3;color:#854d0e}
.btn{border:1px solid #e6eef6;background:white;border-radius:9999px;padding:.35rem .8rem;font-weight:600}
.btn.active{background:linear-gradient(90deg,#38bdf8,#34d399);color:white;border:none}
.no-data{border:2px dashed #e6eef6;border-radius:1rem;padding:2rem;text-align:center;color:#6b7280}
details>summary::-webkit-details-marker{display:none}
summary{cursor:pointer}
table td, table th{padding:.45rem .6rem;border-bottom:1px solid #f1f5f9}
@media (min-width:1024px){ .grid-cols-responsive {grid-template-columns:repeat(3,minmax(0,1fr));} }
@media (min-width:640px) and (max-width:1023px){ .grid-cols-responsive {grid-template-columns:repeat(2,minmax(0,1fr));} }
@media (max-width:639px){ .grid-cols-responsive {grid-template-columns:repeat(1,minmax(0,1fr));} }
</style>
</head>
<body>
<div class="max-w-7xl mx-auto px-5 py-6 space-y-6">
  <!-- Header -->
  <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
    <div>
      <h1 class="text-3xl font-bold text-sky-700 flex items-center gap-3"><i data-lucide="globe"></i> __TITLE__</h1>
      <p class="text-sm text-gray-500">Interactive Nmap report — generated on __GEN_DATE__</p>
    </div>
    <div>
      <input id="searchBox" class="border border-gray-300 rounded-lg px-3 py-2 text-sm w-72 focus:outline-none focus:ring-2 focus:ring-sky-400" placeholder="Search host, service, or port..." />
    </div>
  </div>

  <!-- Logo + stats -->
  <div class="flex flex-col md:flex-row md:items-center gap-4 justify-between bg-gradient-to-r from-sky-50 to-emerald-50 rounded-xl p-4">
    <div class="flex items-center gap-4">
      <img src="https://cdn-icons-png.flaticon.com/512/427/427735.png" alt="logo" class="w-14 h-14 opacity-90"/>
      <div>
        <div class="text-sm text-gray-500">Summary</div>
        <div class="flex items-baseline gap-6">
          <div><div id="sumHosts" class="text-xl font-bold text-sky-600">__TOTAL_HOSTS__</div><div class="text-xs text-gray-500">Hosts</div></div>
          <div><div id="sumPorts" class="text-xl font-bold text-emerald-600">0</div><div class="text-xs text-gray-500">Ports shown</div></div>
          <div><div id="sumServices" class="text-xl font-bold text-indigo-600">__SERVICE_COUNT__</div><div class="text-xs text-gray-500">Services</div></div>
        </div>
      </div>
    </div>
    <div class="hidden md:block text-sm text-gray-500">Multi-select filters available. Search disables pagination.</div>
  </div>

  <!-- Filters -->
  <div class="flex flex-wrap items-center gap-2">
    <button class="btn active" data-filter="all">All</button>
    __FILTER_BUTTONS__
  </div>

  <!-- Hosts grid -->
  <div id="hostContainer" class="grid gap-4 grid-cols-responsive mt-4"></div>
  <div id="noRes" class="no-data hidden">No results found for this view.</div>

  <!-- Pager -->
  <div id="pager" class="flex justify-between items-center mt-4">
    <button id="prevBtn" class="btn">&larr; Prev</button>
    <div class="text-sm text-gray-500">Page <span id="pageNum">1</span> / <span id="pageTotal">1</span></div>
    <button id="nextBtn" class="btn">Next &rarr;</button>
  </div>

  <div class="text-xs text-gray-400 mt-2">Generated by nmap2html (Flask) — please verify results and keep original scan files for auditing.</div>
</div>

<script>
const HOSTS = __DATA__;
let activeFilters = new Set(['all']);
let query = '';
let page = 1;
let pageSize = 9;

function chip(state){
  const s = (state||'').toLowerCase();
  if (s === 'open') return '<span class="chip chip-open">open</span>';
  if (s === 'closed') return '<span class="chip chip-closed">closed</span>';
  return '<span class="chip chip-filtered">'+ (s || 'unknown') +'</span>';
}

function serviceColorClass(service){
  const s = (service||'').toLowerCase();
  if (s.includes('http')) return 'border-l-4 border-sky-400';
  if (s.includes('ssh')) return 'border-l-4 border-green-400';
  if (s.includes('ftp')) return 'border-l-4 border-orange-400';
  if (s.includes('rdp')) return 'border-l-4 border-purple-400';
  if (s.includes('mysql')) return 'border-l-4 border-teal-400';
  return 'border-l-4 border-gray-200';
}

function computeFiltered(){
  const q = query.trim().toLowerCase();
  return HOSTS.map(h=>{
    const hostMatches = !q || (h.address||'').toLowerCase().includes(q) || (h.hostnames||[]).join(',').toLowerCase().includes(q) || h.ports.some(p=>String(p.port).includes(q) || (p.service||'').toLowerCase().includes(q));
    if (!hostMatches) return null;
    const ports = (h.ports || []).filter(p=>{
      const svc = (p.service||'').toLowerCase();
      if (activeFilters.has('all')) return true;
      for (const f of activeFilters){
        if (svc.includes(f)) return true;
      }
      return false;
    });
    return ports.length ? Object.assign({}, h, {ports: ports}) : null;
  }).filter(Boolean);
}

function paginate(list){
  const total = list.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (page > totalPages) page = totalPages;
  const start = (page - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  return { total, totalPages, start, end, pageItems: list.slice(start, end) };
}

function renderHosts(list){
  const c = document.getElementById('hostContainer');
  const noRes = document.getElementById('noRes');
  if (!list.length){
    c.innerHTML = '';
    noRes.classList.remove('hidden');
    return;
  }
  noRes.classList.add('hidden');

  let totalPortsShown = 0;
  c.innerHTML = list.map(h=>{
    const hostnames = (h.hostnames && h.hostnames.length) ? ("<span class='text-gray-400 text-xs'>(" + h.hostnames.join(', ') + ")</span>") : "";
    const mainService = h.ports.length ? h.ports[0].service : '';
    const rows = h.ports.map(p => {
      totalPortsShown += 1;
      return "<tr>" +
               "<td>" + (p.port || "") + "/" + (p.proto || "") + "</td>" +
               "<td>" + chip(p.state) + "</td>" +
               "<td>" + (p.service || "") + "</td>" +
               "<td>" + ((p.product || "") + (p.version ? " " + p.version : "")) + "</td>" +
             "</tr>";
    }).join("");
    return "<details class='card " + serviceColorClass(mainService) + "'>" +
             "<summary class='font-semibold text-sky-700 flex justify-between items-center'>" +
               "<div class='flex items-center gap-3'><i data-lucide='server'></i><span>" + h.address + "</span> " + hostnames + "</div>" +
               "<div class='text-sm text-gray-400'>" + (h.ports.length) + " ports</div>" +
             "</summary>" +
             "<div class='overflow-auto mt-3'><table class='w-full text-sm'><thead class='text-xs text-gray-500'><tr><th class='text-left'>Port</th><th class='text-left'>State</th><th class='text-left'>Service</th><th class='text-left'>Product</th></tr></thead><tbody>" +
               rows +
             "</tbody></table></div>" +
           "</details>";
  }).join("");
  document.getElementById('sumPorts').textContent = totalPortsShown;
  lucide.createIcons();
}

function renderAll(){
  const filtered = computeFiltered();
  const isSearch = query.trim().length > 0;
  const pageData = isSearch ? { total: filtered.length, totalPages: 1, pageItems: filtered } : paginate(filtered);
  renderHosts(pageData.pageItems);
  document.getElementById('pageNum').textContent = page;
  document.getElementById('pageTotal').textContent = pageData.totalPages;
  document.getElementById('pager').style.display = isSearch ? 'none' : 'flex';
}

// wire controls
document.getElementById('searchBox').addEventListener('input', function(e){
  query = e.target.value || '';
  page = 1;
  renderAll();
});

document.getElementById('prevBtn').addEventListener('click', function(){ if (page > 1) { page--; renderAll(); }});
document.getElementById('nextBtn').addEventListener('click', function(){ page++; renderAll(); });

document.querySelectorAll('.btn').forEach(function(b){
  b.addEventListener('click', function(){
    const f = b.getAttribute('data-filter');
    if (!f) return;
    if (f === 'all'){
      activeFilters.clear();
      activeFilters.add('all');
    } else {
      if (activeFilters.has('all')) activeFilters.delete('all');
      if (activeFilters.has(f)) activeFilters.delete(f); else activeFilters.add(f);
      if (activeFilters.size === 0) activeFilters.add('all');
    }
    // update active classes
    document.querySelectorAll('.btn').forEach(function(el){
      const ff = el.getAttribute('data-filter');
      if (ff && activeFilters.has(ff)) el.classList.add('active'); else el.classList.remove('active');
    });
    page = 1;
    renderAll();
  });
});

// init active all
document.querySelectorAll('.btn').forEach(function(el){ if (el.getAttribute('data-filter') === 'all') el.classList.add('active'); });

// initial render
renderAll();
</script>
</body>
</html>
"""

    # build filter buttons
    filter_buttons_html = ""
    for s, icon in filters_to_show:
        filter_buttons_html += f'<button class="btn" data-filter="{esc(s)}">{icon} {esc(s).upper()}</button>'

    html_out = (template
                .replace("__TITLE__", esc(title))
                .replace("__GEN_DATE__", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
                .replace("__DATA__", data_js)
                .replace("__FILTER_BUTTONS__", filter_buttons_html)
                .replace("__TOTAL_HOSTS__", str(len(hosts)))
                .replace("__SERVICE_COUNT__", str(len({p['service'].lower() for h in hosts for p in h['ports'] if p.get('service')})))
               )
    return html_out

# ----------------- Flask routes -----------------
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>nmap2html: Upload Nmap scan</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://unpkg.com/lucide@latest"></script>
<style>
body{font-family:Inter,ui-sans-serif;background:#f8fafc;color:#0f172a}
.card{background:white;border-radius:1rem;padding:1.2rem;box-shadow:0 6px 20px rgba(2,6,23,0.06)}
.k{font-family:monospace}
</style>
</head>
<body>
<div class="max-w-4xl mx-auto px-5 py-8">
  <div class="card">
    <h1 class="text-2xl font-bold">nmap2html — Upload a scan</h1>
    <p class="mt-2 text-sm text-gray-600">Upload an Nmap XML (-oX) or GNMAP (-oG) file to generate a polished HTML report. The generated report can be previewed and downloaded.</p>

    <div class="mt-4">
      <form method="post" action="/upload" enctype="multipart/form-data">
        <label class="block text-sm font-medium text-gray-700">Select scan file</label>
        <input type="file" name="scanfile" accept=".xml,.gnmap" required class="mt-2">
        <div class="mt-3 flex gap-2">
          <button type="submit" class="px-4 py-2 bg-sky-600 text-white rounded">Upload & Generate</button>
          <a href="/" class="px-4 py-2 border rounded text-sm">Reset</a>
        </div>
      </form>
    </div>

    <hr class="my-4">

    <div>
      <h2 class="text-md font-semibold">How to export Nmap scans (recommended)</h2>
      <ul class="list-disc ml-5 text-sm text-gray-700 mt-2">
        <li><span class="k">sudo nmap -sS -sV -p- -T4 &lt;target&gt; -oX scan.xml</span> — XML output (<strong>recommended</strong>).</li>
        <li><span class="k">sudo nmap -sS -sV -p- -T4 &lt;target&gt; -oG scan.gnmap</span> — grepable output (supported).</li>
        <li>Ensure you have permission before scanning production networks.</li>
      </ul>
    </div>

    <div class="mt-4 text-sm text-gray-500">
      <strong>Notes:</strong> file size limit is 20 MB. Only .xml and .gnmap supported. Reports are stored temporarily in the server's <span class="k">reports/</span> folder.
    </div>
  </div>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="mt-4 space-y-2">
        {% for m in messages %}
          <div class="p-3 rounded bg-yellow-50 text-sm text-yellow-800">{{ m|safe }}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

</div>
</body>
</html>
"""

RESULT_HTML = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Report ready</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body>
<div class="max-w-4xl mx-auto px-5 py-8">
  <div class="card">
    <h2 class="text-xl font-semibold">Report generated</h2>
    <p class="mt-2 text-sm text-gray-700">Your HTML report was generated successfully. You can preview it in the browser or download it.</p>

    <div class="mt-4 flex gap-3">
      <a class="px-4 py-2 bg-sky-600 text-white rounded" href="{{ preview_url }}" target="_blank">Preview report</a>
      <a class="px-4 py-2 border rounded" href="{{ download_url }}">Download HTML</a>
      <a class="px-4 py-2 border rounded" href="/">Upload another</a>
    </div>

    <div class="mt-4 text-xs text-gray-500">Report file: <span class="k">{{ filename }}</span></div>
  </div>
</div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

def allowed_file(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload():
    if "scanfile" not in request.files:
        flash("No file part")
        return redirect(url_for("index"))
    f = request.files["scanfile"]
    if f.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))
    if not allowed_file(f.filename):
        flash("Unsupported file extension. Use .xml or .gnmap")
        return redirect(url_for("index"))

    filename = secure_filename(f.filename)
    uid = uuid.uuid4().hex
    ext = filename.rsplit(".", 1)[1].lower()
    stored_name = f"{uid}.{ext}"
    upload_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    f.save(upload_path)

    # parse
    try:
        hosts = load_input(upload_path)
    except Exception as e:
        flash(Markup(f"Failed to parse uploaded file: <strong>{esc(e)}</strong>"))
        return redirect(url_for("index"))

    # generate report HTML
    report_html = generate_html_report(hosts, title=request.form.get("title") or "Nmap Report")
    report_filename = f"report-{uid}.html"
    report_path = os.path.join(app.config["REPORT_FOLDER"], report_filename)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report_html)

    preview_url = url_for("preview_report", filename=report_filename)
    download_url = url_for("download_report", filename=report_filename)
    return render_template_string(RESULT_HTML, preview_url=preview_url, download_url=download_url, filename=report_filename)

@app.route("/reports/<path:filename>", methods=["GET"])
def preview_report(filename):
    # serve the generated HTML (for preview)
    # safe: filename is generated by us (uuid), but we still use send_from_directory
    return send_from_directory(app.config["REPORT_FOLDER"], filename)

@app.route("/download/<path:filename>", methods=["GET"])
def download_report(filename):
    return send_from_directory(app.config["REPORT_FOLDER"], filename, as_attachment=True)

# ----------------- Run -----------------
if __name__ == "__main__":
    # create folders if missing (already created above but keep safe)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    app.run(debug=True, host="0.0.0.0", port=5000)
