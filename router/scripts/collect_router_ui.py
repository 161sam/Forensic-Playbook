#!/usr/bin/env python3
# collect_router_ui.py — robust forensic web-ui collector
# usage: python collect_router_ui.py [--no-headless] [--timeout 10]
import os, sys, time, getpass, argparse, hashlib
from pathlib import Path
from urllib.parse import urljoin
from dotenv import dotenv_values

# selenium imports (run inside venv)
from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

# --- config ---
OUTDIR = Path("/mnt/FORNSIC_20251006")
CONF = OUTDIR / "conf"
SCREEN = OUTDIR / "screenshots"
PCAP = OUTDIR / "pcap"
HASHES = OUTDIR / "hashes"
LOGS = OUTDIR / "logs"

for p in (CONF, SCREEN, PCAP, HASHES, LOGS):
    p.mkdir(parents=True, exist_ok=True)

# pages to collect (extendable)
PAGES = [
    ("root", ""),
    ("port_mapping", "?page=net_port_mapping"),
    ("firewall", "?page=net_firewall"),
    ("general", "?page=net_general"),
    ("ddns", "?page=net_ddns"),
    ("wifi", "?page=wifi_settings"),
    ("status", "?page=status_status"),
    ("event_log", "?page=status_event_log"),
]

# --- CLI args
parser = argparse.ArgumentParser(description="Collect router UI pages for forensics")
parser.add_argument("--no-headless", action="store_true", help="run visible browser")
parser.add_argument("--timeout", type=int, default=8, help="wait time after page load (seconds)")
args = parser.parse_args()

# load optional env
envfile = CONF / "router.env"
env = {}
if envfile.exists():
    env = dotenv_values(envfile)

BASE_URL = env.get("ROUTER_URL") or "https://192.168.0.1/"
USERNAME = env.get("ROUTER_USER") or ""
PASSWORD = env.get("ROUTER_PASS") or ""

if not USERNAME:
    USERNAME = input("Router username (e.g. admin): ")
if PASSWORD is None or PASSWORD == "":
    PASSWORD = getpass.getpass("Router password: ")

# detect geckodriver path
gecko_env = CONF / "gecko_path.env"
GECKO_PATH = None
if gecko_env.exists():
    for line in gecko_env.read_text().splitlines():
        if line.startswith("GECKO_PATH="):
            GECKO_PATH = line.split("=",1)[1].strip()
            break

# selenium setup
opts = Options()
if not args.no_headless:
    opts.headless = True
svc = Service(GECKO_PATH) if GECKO_PATH else Service()

driver = webdriver.Firefox(service=svc, options=opts)
# restrict captured host to router host (reduce memory)
router_host = BASE_URL.replace("https://","").replace("http://","").split("/")[0]
driver.scopes = [r'.*' + router_host + r'.*']

def timestamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

def sha256_file(p: Path):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# chain-of-custody start
coc = LOGS / f"chain_of_custody_collect_{timestamp()}.txt"
with coc.open("a") as f:
    f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} | COLLECT_START | user={os.getlogin()} | host={os.uname().nodename}\n")

# attempt login (heuristic)
def attempt_login():
    driver.get(BASE_URL)
    time.sleep(1.5)
    try:
        pwd = driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
        # pick a reasonable username input
        inputs = driver.find_elements(By.CSS_SELECTOR, 'input[type="text"], input:not([type])')
        user = inputs[0] if inputs else None
        if user:
            user.clear(); user.send_keys(USERNAME)
        pwd.clear(); pwd.send_keys(PASSWORD)
        # try submit
        try:
            btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
            btn.click()
        except:
            pwd.send_keys("\n")
        time.sleep(2.5)
        return True
    except Exception as e:
        print("Automatischer Login nicht möglich, bitte manuell im Browser einloggen und Script erneut starten.")
        return False

ok = attempt_login()
if not ok:
    driver.quit()
    sys.exit(2)

collected = []
# iterate pages and collect artifacts
for name, q in PAGES:
    url = urljoin(BASE_URL, q)
    print("Loading", url)
    driver.get(url)
    time.sleep(args.timeout)
    ts = timestamp()
    htmlp = CONF / f"page_{name}_{ts}.html"
    shotp = SCREEN / f"page_{name}_{ts}.png"
    driver.save_screenshot(str(shotp))
    htmlp.write_text(driver.page_source, encoding="utf-8")
    # pick matching request (best-effort)
    req = None
    for r in reversed(driver.requests):
        if r.host and router_host in r.host:
            if q.strip("?") in r.path or q == "":
                req = r; break
    if not req and driver.requests:
        req = driver.requests[-1]
    metafile = CONF / f"reqmeta_{name}_{ts}.txt"
    meta = []
    if req:
        meta.append(f"=== REQUEST ===\n{req.method} {req.path}\n")
        for k,v in req.headers.items(): meta.append(f"{k}: {v}\n")
        if req.body:
            try:
                mb = req.body.decode("utf-8","ignore")
            except:
                mb = str(req.body)
            meta.append("\n--- REQUEST BODY ---\n")
            meta.append(mb + "\n")
        if req.response:
            meta.append("\n=== RESPONSE ===\n")
            for k,v in req.response.headers.items(): meta.append(f"{k}: {v}\n")
            try:
                rb = req.response.body
                if rb:
                    meta.append("\n--- RESPONSE BODY (first 8192 bytes) ---\n")
                    meta.append(rb[:8192].decode("utf-8","ignore") + "\n")
            except Exception as e:
                meta.append(f"\n--- response body capture failed: {e}\n")
    else:
        meta.append("NO REQUEST FOUND IN BROWSER BUFFER\n")
    metafile.write_text("".join(meta), encoding="utf-8")
    # build curl replay
    if req:
        curl_lines = []
        curl_lines.append(f"curl -k -X {req.method} '{BASE_URL.rstrip('/')}{req.path}' \\")
        for hk,hv in req.headers.items():
            if hk.lower() in ['host','content-length','connection','accept-encoding']:
                continue
            curl_lines.append(f"  -H '{hk}: {hv}' \\")
        if req.body:
            try:
                b = req.body.decode('utf-8','ignore')
                # sichere Quote-Erzeugung für reproduzierbare curl-Calls
                import shlex
                body_quoted = shlex.quote(b)
                curl_lines.append("  --data %s \\" % body_quoted)
            except Exception:
                pass
        curl_lines.append("  -o /dev/null")
        (CONF / f"curl_replay_{name}_{ts}.sh").write_text("\n".join(curl_lines), encoding="utf-8")
    # compute hashes
    for p in (htmlp, shotp, metafile, CONF / f"curl_replay_{name}_{ts}.sh"):
        if p.exists():
            h = sha256_file(p)
            (HASHES / f"{p.name}.sha256").write_text(f"{h}  {p.name}\n", encoding="utf-8")
    collected.append((name, htmlp, shotp, metafile))
    print("Saved:", htmlp.name, shotp.name, metafile.name)

# final manifest
manifest = LOGS / f"collect_manifest_{timestamp()}.txt"
with manifest.open("w") as m:
    m.write(f"collect manifest\nstarted: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    m.write(f"user: {os.getlogin()}\nhost: {os.uname().nodename}\nbase_url: {BASE_URL}\n\nfiles:\n")
    for n,htmlp,shotp,metafile in collected:
        if htmlp.exists():
            m.write(f"{htmlp}\n")
        if shotp.exists():
            m.write(f"{shotp}\n")
        if metafile.exists():
            m.write(f"{metafile}\n")
    m.write("\nhashes directory: " + str(HASHES) + "\n")
print("Collection complete. Manifest:", manifest)
with coc.open("a") as f:
    f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} | COLLECT_END | files={len(collected)}\n")

driver.quit()
