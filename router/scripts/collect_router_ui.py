#!/usr/bin/env python3
# collect_router_ui.py — forensic web UI collector (wire-capable or selenium-only fallback)
from pathlib import Path
import os, sys, time, getpass, hashlib, shlex, subprocess
from urllib.parse import urljoin
from dotenv import dotenv_values

OUTDIR = Path("/mnt/FORNSIC_20251006")
CONF = OUTDIR / "conf"
SCREEN = OUTDIR / "screenshots"
PCAP = OUTDIR / "pcap"
HASHES = OUTDIR / "hashes"
LOGS = OUTDIR / "logs"

for p in (CONF, SCREEN, PCAP, HASHES, LOGS):
    p.mkdir(parents=True, exist_ok=True)

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

def ts(): return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

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
gp = CONF / "gecko_path.env"
GECKO_PATH = None
if gp.exists():
    for line in gp.read_text().splitlines():
        if line.strip().startswith("GECKO_PATH="):
            GECKO_PATH = line.split("=",1)[1].strip()
            break

# try to import selenium-wire; fallback gracefully
use_wire = True
try:
    from seleniumwire import webdriver as wire_webdriver  # type: ignore
except Exception:
    use_wire = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
except Exception as e:
    print("ERROR: selenium not installed in venv. Activate venv and pip install selenium. Exiting.")
    raise

# prepare driver service
svc = Service(GECKO_PATH) if GECKO_PATH else Service()
opts = Options()
opts.headless = True

if use_wire:
    driver = wire_webdriver.Firefox(service=svc, options=opts)
    print("selenium-wire available — using wire for request/response capture.")
    host = BASE_URL.replace("https://","").replace("http://","").split("/")[0]
    driver.scopes = [r'.*' + host + r'.*']
else:
    driver = webdriver.Firefox(service=svc, options=opts)
    print("selenium-wire not present — using selenium-only fallback (will create curl replays with cookies).")

router_host = BASE_URL.replace("https://","").replace("http://","").split("/")[0]

# chain-of-custody log
coc = HASHES / f"chain_of_custody_collect_{ts()}.txt"
with coc.open("a") as f:
    f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} | COLLECT_START | user={os.getlogin()} | host={os.uname().nodename}\n")

# attempt login heuristically
def attempt_login():
    driver.get(BASE_URL)
    time.sleep(1.5)
    try:
        pwd = driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
        inputs = driver.find_elements(By.CSS_SELECTOR, 'input[type="text"], input:not([type])')
        user = inputs[0] if inputs else None
        if user:
            user.clear(); user.send_keys(USERNAME)
        pwd.clear(); pwd.send_keys(PASSWORD)
        try:
            btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
            btn.click()
        except:
            pwd.send_keys("\n")
        time.sleep(2.5)
        return True
    except Exception:
        print("Automated login not detected. Please login manually in a browser session and restart script.")
        return False

ok = attempt_login()
if not ok:
    driver.quit(); sys.exit(2)

collected = []
for name, query in PAGES:
    url = urljoin(BASE_URL, query)
    print("Loading", url)
    driver.get(url)
    time.sleep(3)
    t = ts()
    htmlp = CONF / f"page_{name}_{t}.html"
    shotp = SCREEN / f"page_{name}_{t}.png"
    htmlp.write_text(driver.page_source, encoding="utf-8")
    driver.save_screenshot(str(shotp))

    metafile = CONF / f"reqmeta_{name}_{t}.txt"
    curlfile = CONF / f"curl_replay_{name}_{t}.sh"
    meta_lines = []

    if use_wire:
        # pick most relevant request
        req = None
        for r in reversed(driver.requests):
            if r.host and router_host in r.host:
                if query.strip("?") in r.path or query == "":
                    req = r; break
        if not req and driver.requests:
            req = driver.requests[-1]
        if req:
            meta_lines.append(f"=== REQUEST ===\n{req.method} {req.path}\n")
            for k,v in req.headers.items(): meta_lines.append(f"{k}: {v}\n")
            if req.body:
                try:
                    mb = req.body.decode('utf-8','ignore')
                except:
                    mb = str(req.body)
                meta_lines.append("\n--- REQUEST BODY ---\n")
                meta_lines.append(mb + "\n")
            if req.response:
                meta_lines.append("\n=== RESPONSE ===\n")
                for k,v in req.response.headers.items(): meta_lines.append(f"{k}: {v}\n")
                try:
                    rb = req.response.body
                    if rb:
                        meta_lines.append("\n--- RESPONSE BODY (first 8192 bytes) ---\n")
                        meta_lines.append(rb[:8192].decode('utf-8','ignore') + "\n")
                except Exception as e:
                    meta_lines.append(f"\n--- RESPONSE BODY capture error: {e}\n")
            # build curl replay
            curl_parts = [f"curl -k -X {req.method} '{BASE_URL.rstrip('/')}{req.path}' \\"]
            for hk,hv in req.headers.items():
                if hk.lower() in ['host','content-length','connection','accept-encoding']:
                    continue
                curl_parts.append(f"  -H '{hk}: {hv}' \\")
            if req.body:
                try:
                    b = req.body.decode('utf-8','ignore')
                    curl_parts.append("  --data " + shlex.quote(b) + " \\")
                except:
                    pass
            curl_parts.append("  -o /dev/null")
            curlfile.write_text("\n".join(curl_parts), encoding="utf-8")
        else:
            meta_lines.append("NO REQUEST FOUND IN WIRE BUFFER\n")
    else:
        # selenium-only: extract cookies and perform curl to capture headers/body (read-only)
        cookies = driver.get_cookies()
        cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        safe_url = BASE_URL.rstrip("/") + query
        headers_out = CONF / f"headers_{name}_{t}.txt"
        body_out = CONF / f"pagebody_{name}_{t}.html"
        curl_cmd = [
            "curl", "-k", "-sS", "-D", str(headers_out), "-o", str(body_out),
            "-H", f"Cookie: {cookie_header}", safe_url
        ]
        try:
            subprocess.run(curl_cmd, check=True)
            # reproducible replay file
            curl_replay = ["#!/usr/bin/env bash",
                           "# curl replay using extracted cookies (read-only)",
                           "curl -k -sS -D '{}' -o '{}' -H 'Cookie: {}' '{}'".format(
                                headers_out.name, body_out.name, cookie_header, safe_url)]
            curlfile.write_text("\n".join(curl_replay), encoding="utf-8")
            meta_lines.append(f"=== CURL REPLAY GENERATED: {curlfile.name} ===\n")
        except subprocess.CalledProcessError as e:
            meta_lines.append(f"CURL FAILED: {e}\n")

    metafile.write_text("".join(meta_lines), encoding="utf-8")

    # write hashes
    for p in (htmlp, shotp, metafile, curlfile):
        if p.exists():
            h = sha256_file(p)
            (HASHES / f"{p.name}.sha256").write_text(f"{h}  {p.name}\n", encoding="utf-8")

    collected.append((name, htmlp, shotp, metafile, curlfile))
    print("Saved:", htmlp.name, shotp.name, metafile.name, curlfile.name)

# final manifest
manifest = LOGS / f"collect_manifest_{ts()}.txt"
with manifest.open("w") as m:
    m.write("collect manifest\n")
    m.write(f"started: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    m.write(f"user: {os.getlogin()}\nhost: {os.uname().nodename}\nbase_url: {BASE_URL}\n\nfiles:\n")
    for n,htmlp,shotp,meta,curl in collected:
        if htmlp.exists(): m.write(f"{htmlp}\n")
        if shotp.exists(): m.write(f"{shotp}\n")
        if meta.exists(): m.write(f"{meta}\n")
        if curl.exists(): m.write(f"{curl}\n")
    m.write("\nhashes dir: " + str(HASHES) + "\n")
print("Collection finished. Manifest:", manifest)

with (HASHES / f"chain_of_custody_collect_{ts()}.txt").open("a") as f:
    f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} | COLLECT_END | files={len(collected)}\n")

driver.quit()
