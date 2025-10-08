#!/usr/bin/env python3
# collect_router_ui.py — robust router UI collector with auto-login + interactive fallback
# - Reads /mnt/FORNSIC_20251006/conf/router.env (optional)
# - Auto-login using username/password (or prompt)
# - If auto-login fails: relaunch browser visible and wait for manual login
# - Uses selenium-wire if available (request/response capture). Otherwise selenium-only and curl replays.
# - Produces: page_*.html, screenshots, reqmeta_*.txt, curl_replay_*.sh, hashes, manifest, Chain-of-Custody
#
# Usage:
#   source /mnt/FORNSIC_20251006/venv/bin/activate
#   python /mnt/FORNSIC_20251006/conf/collect_router_ui.py [--no-headless] [--timeout 4] [--interactive]
#
import argparse
import getpass
import hashlib
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
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

def timestamp(): return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
def now_iso(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def sha256_file(p: Path):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# CLI args
parser = argparse.ArgumentParser()
parser.add_argument("--no-headless", action="store_true", help="start browser visible from the start")
parser.add_argument("--timeout", type=int, default=4, help="wait (seconds) after page loads")
parser.add_argument("--interactive", action="store_true", help="force interactive manual login (visible browser)")
args = parser.parse_args()

# load env
envf = CONF / "router.env"
env = {}
if envf.exists():
    env = dotenv_values(envf)
BASE_URL = env.get("ROUTER_URL") or "https://192.168.0.1/"
ROUTER_HOST = (
    BASE_URL.replace("https://", "").replace("http://", "").split("/")[0]
)
USERNAME = env.get("ROUTER_USER") or ""
PASSWORD = env.get("ROUTER_PASS") or ""

if not USERNAME:
    USERNAME = input("Router username (e.g. admin): ").strip()
if PASSWORD is None or PASSWORD == "":
    PASSWORD = getpass.getpass("Router password (input hidden): ")

# geckodriver path if provided
gp = CONF / "gecko_path.env"
GECKO_PATH = None
if gp.exists():
    for line in gp.read_text().splitlines():
        if line.strip().startswith("GECKO_PATH="):
            GECKO_PATH = line.split("=",1)[1].strip()
            break

# Try selenium-wire, fallback to selenium-only
use_wire = False
try:
    from seleniumwire import webdriver as wire_webdriver  # type: ignore
    use_wire = True
except Exception:
    use_wire = False

# Import selenium
try:
    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException
    from selenium.webdriver.common.by import By
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
except Exception:
    print("ERROR: selenium is not available in this Python environment. Activate venv and pip install selenium.")
    raise

# prepare driver factory to allow relaunching visible/hidden
def build_driver(headless: bool):
    svc = Service(GECKO_PATH) if GECKO_PATH else Service()
    opts = Options()
    opts.headless = headless
    if use_wire:
        drv = wire_webdriver.Firefox(service=svc, options=opts)
        # limit capture to router host to reduce memory traffic
        drv.scopes = [rf".*{ROUTER_HOST}.*"]
    else:
        drv = webdriver.Firefox(service=svc, options=opts)
    return drv

# Chain-of-custody helper
coc_file = HASHES / f"chain_of_custody_collect_{timestamp()}.txt"
def coc(msg):
    with coc_file.open("a") as f:
        f.write(f"{now_iso()} | {msg}\n")

coc(f"START_COLLECT user={os.getlogin()} host={os.uname().nodename} base_url={BASE_URL}")

# Heuristics to detect login form and to find username field
def find_login_fields(driver):
    # returns tuple (user_elem, pass_elem) or (None, None)
    try:
        pass_el = driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
    except Exception:
        return (None, None)
    # try many heuristics to get username
    cand_selectors = [
        'input[type="text"]',
        'input[name*=user]',
        'input[id*=user]',
        'input[name*=login]',
        'input[id*=login]',
        'input[placeholder*=User]',
        'input[placeholder*=user]',
        'input:not([type])'
    ]
    user_el = None
    for sel in cand_selectors:
        try:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            if els:
                user_el = els[0]
                break
        except Exception:
            continue
    return (user_el, pass_el)

def submit_login_fields(user_el, pass_el, username, password):
    try:
        if user_el:
            user_el.clear()
            user_el.send_keys(username)
        pass_el.clear()
        pass_el.send_keys(password)
        # try to submit by finding visible submit button nearby
        try:
            # look for button within form
            form = None
            el = pass_el
            for _ in range(4):
                try:
                    form = el.find_element(By.XPATH, './ancestor::form')
                    break
                except Exception:
                    try:
                        el = el.find_element(By.XPATH, '..')
                    except Exception:
                        break
            if form:
                # attempt to find submit inside form
                try:
                    btns = form.find_elements(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                    if btns:
                        btns[0].click()
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        # fallback: press Enter on password field
        pass_el.send_keys("\n")
        return True
    except Exception:
        return False

def is_logged_in(driver, timeout=6):
    # heuristics: login form absent OR presence of logout / session elements / dashboard text
    end = time.time() + timeout
    while time.time() < end:
        try:
            # if password field still present => not logged in
            if len(driver.find_elements(By.CSS_SELECTOR, 'input[type="password"]')) == 0:
                # try to detect logout or dashboard hints
                body = driver.page_source.lower()
                if "logout" in body or "abmelden" in body or "dashboard" in body or "overview" in body or "status" in body:
                    return True
                # absence of password with some content is likely logged in
                return True
            else:
                time.sleep(0.6)
        except Exception:
            time.sleep(0.6)
    return False

# Main: try to auto-login; if fail -> interactive visible fallback
headless = False if (args.no_headless or args.interactive) else True
driver = None
try:
    driver = build_driver(headless=headless)
except WebDriverException as e:
    print("ERROR: Could not start webdriver. Check geckodriver and that X is available for visible mode.")
    coc(f"WEBDRIVER_START_ERROR {e}")
    raise

# Check connectivity to BASE_URL first (simple GET)
def check_reachable(drv, url, tries=3, wait=1.5):
    for _ in range(tries):
        try:
            drv.get(url)
            time.sleep(1.0)
            # if page is a neterror, webdriver will raise — we catch below
            return True
        except WebDriverException:
            # Connection failures may occur; retry
            time.sleep(wait)
    return False

if not check_reachable(driver, BASE_URL, tries=3):
    print(f"ERROR: Router at {BASE_URL} not reachable from this host/browser. Check cable/power/IP.")
    coc("ROUTER_NOT_REACHABLE")
    driver.quit()
    sys.exit(3)

# Attempt auto login if login form present
auto_login_success = False
try:
    u_el, p_el = find_login_fields(driver)
    if p_el:
        # we have a login form visible
        coc("LOGIN_FORM_DETECTED")
        ok_submit = submit_login_fields(u_el, p_el, USERNAME, PASSWORD)
        if ok_submit:
            # wait and check
            if is_logged_in(driver, timeout=6):
                auto_login_success = True
                coc("AUTO_LOGIN_SUCCESS")
            else:
                coc("AUTO_LOGIN_ATTEMPT_FAILED")
        else:
            coc("AUTO_LOGIN_SUBMIT_FAILED")
    else:
        # no password field -> likely already logged in or different auth
        if is_logged_in(driver, timeout=2):
            auto_login_success = True
            coc("NO_LOGIN_FORM_ASSUMED_LOGGED_IN")
        else:
            coc("NO_LOGIN_FORM_AND_NOT_LOGGED_IN")
except Exception as e:
    coc(f"AUTO_LOGIN_EXCEPTION {e}")

if not auto_login_success:
    # If headless currently True, we need to relaunch visible browser for manual login
    if headless:
        coc("AUTO_LOGIN_FAILED_SWITCH_TO_INTERACTIVE")
        print("\nAuto-login failed. Launching visible browser to allow manual login.")
        try:
            driver.quit()
        except Exception:
            pass
        driver = build_driver(headless=False)
        # open login page visibly
        driver.get(BASE_URL)
        print("Please perform manual login in the opened Firefox window. Once logged in, either:")
        print(" - Press Enter here to continue, OR")
        print(" - Wait; script will try to detect login automatically (timeout 300s).")
        coc("AWAIT_MANUAL_LOGIN_START")
        # wait for login detect OR user Enter
        start = time.time()
        timeout_manual = 300  # 5 minutes
        logged = False
        while time.time() - start < timeout_manual:
            # check every 2s
            if is_logged_in(driver, timeout=2):
                logged = True
                coc("MANUAL_LOGIN_DETECTED_AUTOMATIC")
                print("Login detected automatically.")
                break
            # non-blocking check if user pressed Enter
            print("Press Enter to continue after manual login (or wait for auto-detect)...", end="", flush=True)
            try:
                # use select on stdin for a short timeout to not block indefinitely
                import select
                import sys as _sys
                rlist, _, _ = select.select([_sys.stdin], [], [], 2.0)
                if rlist:
                    _ = _sys.stdin.readline()
                    if is_logged_in(driver, timeout=2):
                        logged = True
                        coc("MANUAL_LOGIN_CONFIRMED_BY_USER")
                        break
                    else:
                        print("Manual login not detected yet. Continue logging in and press Enter again when finished.")
                        continue
            except Exception:
                # fallback simple sleep
                time.sleep(2)
        if not logged:
            print("Manual login not detected within timeout. Exiting to avoid unprivileged changes.")
            coc("MANUAL_LOGIN_TIMEOUT")
            driver.quit()
            sys.exit(4)
    else:
        # visible mode but still failed auto-login (user likely wanted manual)
        print("Auto-login failed. You're running visible browser mode; please login manually in the opened window.")
        coc("AUTO_LOGIN_FAILED_VISIBLE_WAITING")
        # Wait for manual login (press Enter)
        input("After you completed login in the browser, press Enter here to continue...")
        if not is_logged_in(driver, timeout=6):
            print("Login not detected after user confirmation. Exiting.")
            coc("MANUAL_LOGIN_USER_CONFIRMED_BUT_NOT_DETECTED")
            driver.quit()
            sys.exit(5)

# At this point we are logged in (auto or manual)
coc("LOGIN_CONFIRMED, starting collection")
time.sleep(1)

# collection loop
collected = []
for name, q in PAGES:
    full = urljoin(BASE_URL, q)
    print("Collecting:", full)
    try:
        driver.get(full)
    except WebDriverException as e:
        print("Warning: driver failed to load", full, ":", e)
        coc(f"PAGE_LOAD_ERROR {full} {e}")
        # continue to next
        continue
    time.sleep(args.timeout)
    ts = timestamp()
    htmlp = CONF / f"page_{name}_{ts}.html"
    shotp = SCREEN / f"page_{name}_{ts}.png"
    htmlp.write_text(driver.page_source, encoding="utf-8")
    driver.save_screenshot(str(shotp))
    metaf = CONF / f"reqmeta_{name}_{ts}.txt"
    curlf = CONF / f"curl_replay_{name}_{ts}.sh"
    meta_lines = []
    # If selenium-wire active and available, prefer detailed request/response capture
    if use_wire:
        # find last matching request
        req = None
        for r in reversed(driver.requests):
            try:
                if r.host and ROUTER_HOST in r.host:
                    if q.strip("?") in r.path or q == "":
                        req = r
                        break
            except Exception:
                continue
        if not req and driver.requests:
            req = driver.requests[-1]
        if req:
            meta_lines.append(f"=== REQUEST ===\n{req.method} {req.path}\n")
            for key, value in req.headers.items():
                meta_lines.append(f"{key}: {value}\n")
            if req.body:
                try:
                    mb = req.body.decode('utf-8','ignore')
                except Exception:
                    mb = str(req.body)
                meta_lines.append("\n--- REQUEST BODY ---\n")
                meta_lines.append(mb + "\n")
            if req.response:
                meta_lines.append("\n=== RESPONSE ===\n")
                for key, value in req.response.headers.items():
                    meta_lines.append(f"{key}: {value}\n")
                try:
                    rb = req.response.body
                    if rb:
                        meta_lines.append("\n--- RESPONSE BODY (first 8192 bytes) ---\n")
                        meta_lines.append(rb[:8192].decode('utf-8','ignore') + "\n")
                except Exception as e:
                    meta_lines.append(f"\n--- RESPONSE BODY capture error: {e}\n")
            # build curl
            curl_parts = [f"curl -k -X {req.method} '{BASE_URL.rstrip('/')}{req.path}' \\"]
            for hk, hv in req.headers.items():
                if hk.lower() in ['host','content-length','connection','accept-encoding']:
                    continue
                curl_parts.append(f"  -H '{hk}: {hv}' \\")
            if req.body:
                try:
                    b = req.body.decode('utf-8','ignore')
                    curl_parts.append("  --data " + shlex.quote(b) + " \\")
                except Exception:
                    pass
            curl_parts.append("  -o /dev/null")
            curlf.write_text("\n".join(curl_parts), encoding="utf-8")
        else:
            meta_lines.append("NO REQUEST FOUND IN WIRE BUFFER\n")
    else:
        # selenium-only: extract cookies and perform read-only curl to capture server headers/body
        try:
            cookies = driver.get_cookies()
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            safe_url = BASE_URL.rstrip("/") + q
            headers_out = CONF / f"headers_{name}_{ts}.txt"
            body_out = CONF / f"pagebody_{name}_{ts}.html"
            curl_cmd = [
                "curl", "-k", "-sS", "-D", str(headers_out), "-o", str(body_out),
                "-H", f"Cookie: {cookie_header}", safe_url
            ]
            subprocess.run(curl_cmd, check=True)
            curl_replay_lines = [
                "#!/usr/bin/env bash",
                f"# curl replay for page {name}",
                f"curl -k -sS -D '{headers_out.name}' -o '{body_out.name}' -H 'Cookie: {cookie_header}' '{safe_url}'"
            ]
            curlf.write_text("\n".join(curl_replay_lines), encoding="utf-8")
            meta_lines.append(f"CURL_REPLAY_CREATED {curlf.name}\n")
        except Exception as e:
            meta_lines.append(f"CURL_CAPTURE_FAILED {e}\n")
    metaf.write_text("".join(meta_lines), encoding="utf-8")
    # write hashes for artifacts
    for p in (htmlp, shotp, metaf, curlf):
        if p.exists():
            (HASHES / f"{p.name}.sha256").write_text(f"{sha256_file(p)}  {p.name}\n", encoding="utf-8")
    collected.append((name, htmlp, shotp, metaf, curlf))
    print("Saved:", htmlp.name, shotp.name, metaf.name, curlf.name)

# final manifest
man = LOGS / f"collect_manifest_{timestamp()}.txt"
with man.open("w") as f:
    f.write("collect manifest\n")
    f.write(f"started: {now_iso()}\nuser: {os.getlogin()}\nhost: {os.uname().nodename}\nbase_url: {BASE_URL}\n\nfiles:\n")
    for _, htmlp, shotp, meta, curl in collected:
        if htmlp.exists():
            f.write(f"{htmlp}\n")
        if shotp.exists():
            f.write(f"{shotp}\n")
        if meta.exists():
            f.write(f"{meta}\n")
        if curl.exists():
            f.write(f"{curl}\n")
    f.write("\nhashes dir: " + str(HASHES) + "\n")
print("Collection finished. Manifest:", man)
coc(f"COLLECT_FINISHED files={len(collected)} manifest={man.name}")

driver.quit()
