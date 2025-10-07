#!/usr/bin/env python3
# timeline_builder.py
import os, sys, subprocess, json, datetime, re

EVIDIR = sys.argv[1] if len(sys.argv)>1 else "."
out = []

def add(label, ts, src):
    out.append((ts, label, src))

# 1) package-lock / yarn.lock mtimes in repos
roots = ["/home/saschi/InfoTerminal","/home/saschi/Sprachassistent","/home/saschi/agent-nn"]
for r in roots:
    for f in ("package-lock.json","yarn.lock"):
        p = os.path.join(r,f)
        if os.path.exists(p):
            ts = datetime.datetime.utcfromtimestamp(os.path.getmtime(p)).isoformat()+"Z"
            add(f"lockfile-modified {r}/{f}", ts, p)

# 2) npm logs (if present) - parse timestamps for install events
npm_logs = ["/home/saschi/.npm/_logs"]
for base in npm_logs:
    for root,dirs,files in os.walk(base):
        for fn in files:
            p = os.path.join(root,fn)
            try:
                with open(p,"r",errors="ignore") as fh:
                    data = fh.read(5120)
                    m = re.search(r'"time":"([^"]+)"', data)
                    if m:
                        add(f"npmlog {fn}", m.group(1), p)
            except Exception:
                pass

# 3) journalctl - grep npm / node / apt (last 30 days)
try:
    outp = subprocess.check_output(["journalctl","-o","short-iso","_COMM=npm","--since","-30d"], text=True, stderr=subprocess.DEVNULL)
    for line in outp.splitlines()[:500]:
        if line.strip():
            # line e.g. "2025-10-03T18:32:01+00:00 hostname ..."
            m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
            if m:
                add("journal npm", m.group(1)+"Z", line)
except Exception:
    pass

# 4) router dump timestamps — look for files in /mnt/forensic_evidence router dumps
for root,dirs,files in os.walk(EVIDIR):
    for fn in files:
        if "router" in fn.lower() or "tr69" in fn.lower() or fn.lower().endswith(".cfg"):
            p = os.path.join(root,fn)
            ts = datetime.datetime.utcfromtimestamp(os.path.getmtime(p)).isoformat()+"Z"
            add("router-dump", ts, p)

# Output sorted timeline
out_sorted = sorted(out, key=lambda x: x[0])
with open(os.path.join(EVIDIR,"timeline_router_corruption.txt"), "w") as fh:
    for ts,label,src in out_sorted:
        fh.write(f"{ts}\t{label}\t{src}\n")
print("Wrote timeline_router_corruption.txt")
