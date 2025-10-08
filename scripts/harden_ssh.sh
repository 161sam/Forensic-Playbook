
#!/usr/bin/env bash
# Harden SSH + fail2ban (safe one-shot)
# Steps: (2) sshd hardening  (3) fail2ban  (4) quick checks  (5) optional acct cleanup  (6) optional extras
# Options (export before running or pass inline like VAR=1 bash harden_ssh.sh):
#   FORCE_KEYS_ONLY=1        # disable password auth even if no key is found for admin
#   RESTRICT_TO_ADMIN=1      # set AllowUsers to the detected admin only
#   SWITCH_PORT=1            # change SSH port (default 2222)
#   SSH_PORT=2222            # target port if SWITCH_PORT=1
#   APPLY_ACCOUNT_HARDEN=1   # change shells for risky default accounts (only if they have interactive shells)
set -u

log(){ printf "\n==> %s\n" "$*"; }
warn(){ printf "\n[WARN] %s\n" "$*" >&2; }
die(){ printf "\n[ERROR] %s\n" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."

# --- Detect environment ---
ADMIN="${SUDO_USER:-${USER:-root}}"
if [ "$ADMIN" = "root" ] && id -u root >/dev/null 2>&1; then
  ADMIN_HOME="$(getent passwd root | cut -d: -f6)"
else
  getent passwd "$ADMIN" >/dev/null 2>&1 || die "Admin user '$ADMIN' not found."
  ADMIN_HOME="$(getent passwd "$ADMIN" | cut -d: -f6)"
fi
KEYFILE="$ADMIN_HOME/.ssh/authorized_keys"

APT=0 DNF=0 YUM=0
command -v apt-get >/dev/null 2>&1 && APT=1
command -v dnf     >/dev/null 2>&1 && DNF=1
[ $DNF -eq 0 ] && command -v yum >/dev/null 2>&1 && YUM=1

UFW_ACTIVE=0; command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "active" && UFW_ACTIVE=1
FWD_ACTIVE=0; command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && FWD_ACTIVE=1
NFT_PRESENT=0; command -v nft >/dev/null 2>&1 && NFT_PRESENT=1

SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
SSHD_CONF="/etc/ssh/sshd_config"
[ -x "$SSHD_BIN" ] || die "sshd not found."

# --- (2) SSHD hardening ---
log "Backing up sshd_config and applying hardening…"
cp -a "$SSHD_CONF" "${SSHD_CONF}.bak-$(date +%F-%H%M%S)" || die "Failed to backup $SSHD_CONF"

# Detect if admin has at least one public key
HAS_KEY=0
if [ -f "$KEYFILE" ] && grep -qE '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp)' "$KEYFILE"; then HAS_KEY=1; fi
PASS_AUTH="no"
if [ $HAS_KEY -eq 0 ] && [ "${FORCE_KEYS_ONLY:-0}" -ne 1 ]; then
  PASS_AUTH="yes"
  warn "No public key found for $ADMIN at $KEYFILE — leaving PasswordAuthentication enabled to avoid lockout."
fi

# Remove existing occurrences of directives we manage
sed -i -E '
/^\s*PermitRootLogin\s+/d;
/^\s*PasswordAuthentication\s+/d;
/^\s*KbdInteractiveAuthentication\s+/d;
/^\s*ChallengeResponseAuthentication\s+/d;
/^\s*PubkeyAuthentication\s+/d;
/^\s*AuthenticationMethods\s+/d;
/^\s*MaxAuthTries\s+/d;
/^\s*LoginGraceTime\s+/d;
/^\s*LogLevel\s+/d;
/^\s*AllowUsers\s+/d;
/^\s*Port\s+[0-9]+\s*$/d' "$SSHD_CONF"

# Append our managed block
{
  echo ""
  echo "# --- BEGIN managed hardening block ($(date -Is)) ---"
  echo "PermitRootLogin no"
  echo "PasswordAuthentication $PASS_AUTH"
  echo "KbdInteractiveAuthentication no"
  echo "ChallengeResponseAuthentication no"
  echo "PubkeyAuthentication yes"
  echo "AuthenticationMethods publickey"
  echo "MaxAuthTries 3"
  echo "LoginGraceTime 20"
  echo "LogLevel VERBOSE"
  if [ "${RESTRICT_TO_ADMIN:-0}" -eq 1 ]; then
    echo "AllowUsers $ADMIN"
  fi
  if [ "${SWITCH_PORT:-0}" -eq 1 ]; then
    echo "Port ${SSH_PORT:-2222}"
  fi
  echo "# --- END managed hardening block ---"
} >> "$SSHD_CONF"

# If switching port, open it in firewall + SELinux before reload
if [ "${SWITCH_PORT:-0}" -eq 1 ]; then
  NEWPORT="${SSH_PORT:-2222}"
  log "Preparing firewall/SELinux for new SSH port $NEWPORT…"
  if [ $UFW_ACTIVE -eq 1 ]; then
    ufw allow "${NEWPORT}/tcp" || warn "UFW: failed to allow $NEWPORT/tcp"
  fi
  if [ $FWD_ACTIVE -eq 1 ]; then
    firewall-cmd --permanent --add-port="${NEWPORT}/tcp" || warn "firewalld: failed to allow $NEWPORT/tcp"
    firewall-cmd --reload || warn "firewalld: reload failed"
  fi
  # SELinux port mapping
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    if ! command -v semanage >/dev/null 2>&1; then
      if [ $DNF -eq 1 ] || [ $YUM -eq 1 ]; then
        (command -v dnf >/dev/null && dnf -y install policycoreutils-python-utils) >/dev/null 2>&1 || true
        (command -v yum >/dev/null && yum -y install policycoreutils-python) >/dev/null 2>&1 || true
      elif [ $APT -eq 1 ]; then
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y policycoreutils-python-utils >/dev/null 2>&1 || true
      fi
    fi
    if command -v semanage >/dev/null 2>&1; then
      semanage port -l | grep -qE "ssh_port_t.*\\b${NEWPORT}\\b" || semanage port -a -t ssh_port_t -p tcp "$NEWPORT" || true
    else
      warn "SELinux enforcing but semanage not available — ensure ssh_port_t includes $NEWPORT."
    fi
  fi
fi

# Validate and reload sshd
log "Validating sshd config…"
if ! "$SSHD_BIN" -t; then
  mv -f "${SSHD_CONF}.bak-"* "$SSHD_CONF".restore 2>/dev/null || true
  die "sshd config test failed. Restored backup to $SSHD_CONF.restore"
fi
log "Reloading sshd…"
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || warn "Could not reload sshd; you may need to restart it manually."

# --- (3) Fail2ban ---
log "Installing and configuring fail2ban…"
if [ $APT -eq 1 ]; then
  apt-get update -y && apt-get install -y fail2ban
elif [ $DNF -eq 1 ] || [ $YUM -eq 1 ]; then
  # ensure EPEL for fail2ban
  (command -v dnf >/dev/null && dnf -y install epel-release) >/dev/null 2>&1 || true
  (command -v yum >/dev/null && yum -y install epel-release) >/dev/null 2>&1 || true
  (command -v dnf >/dev/null && dnf -y install fail2ban) || (command -v yum >/dev/null && yum -y install fail2ban)
else
  warn "No supported package manager found; skip fail2ban install."
fi

mkdir -p /etc/fail2ban/jail.d
cat >/etc/fail2ban/jail.d/10-sshd.conf <<'EOF'
[sshd]
enabled = true
maxretry = 3
findtime = 10m
bantime = 1d
backend = systemd
ignoreip = 127.0.0.1/8 ::1
EOF

systemctl enable --now fail2ban >/dev/null 2>&1 || warn "Failed to enable/start fail2ban."
systemctl restart fail2ban >/dev/null 2>&1 || true

# --- (4) Quick compromise checks (report only) ---
log "Quick checks (report only)…"
REPORT="/root/ssh_quickcheck_$(date +%F-%H%M%S).txt"
{
  echo "# Accepted SSH logins last 48h:"
  zgrep -hEi 'Accepted (publickey|password)' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 200 || echo "(none found in recent logs)"

  echo -e "\n# Users with interactive shells:"
  getent passwd | awk -F: '$7 ~ /(bash|zsh|ash|ksh|fish|sh)$/ {printf "%-16s %-30s %s\n",$1,$6,$7}'

  echo -e "\n# Members of sudo/wheel/docker groups:"
  getent group sudo  2>/dev/null || true
  getent group wheel 2>/dev/null || true
  getent group docker 2>/dev/null || true
} > "$REPORT"
log "Wrote: $REPORT"

# --- (5) Optional account cleanup ---
DEFAULT_ACCTS=(ftp mysql postgres ubuntu oracle test user gitlab jenkins)
if [ "${APPLY_ACCOUNT_HARDEN:-0}" -eq 1 ]; then
  log "Applying conservative account shell hardening…"
  NOLOGIN="$(command -v nologin || true)"
  [ -z "$NOLOGIN" ] && [ -x /usr/sbin/nologin ] && NOLOGIN="/usr/sbin/nologin"
  [ -z "$NOLOGIN" ] && [ -x /sbin/nologin ] && NOLOGIN="/sbin/nologin"
  [ -z "$NOLOGIN" ] && NOLOGIN="/bin/false"
  for u in "${DEFAULT_ACCTS[@]}"; do
    if getent passwd "$u" >/dev/null; then
      CURSHELL="$(getent passwd "$u" | cut -d: -f7)"
      if echo "$CURSHELL" | grep -qE '(bash|zsh|ash|ksh|fish|/sh)$'; then
        usermod -s "$NOLOGIN" "$u" && echo "  -> set $u shell to $NOLOGIN"
      fi
    fi
  done
else
  log "Dry-run: showing default accounts that WOULD be switched to nologin (set APPLY_ACCOUNT_HARDEN=1 to apply):"
  for u in "${DEFAULT_ACCTS[@]}"; do
    if getent passwd "$u" >/dev/null; then
      CURSHELL="$(getent passwd "$u" | cut -d: -f7)"
      if echo "$CURSHELL" | grep -qE '(bash|zsh|ash|ksh|fish|/sh)$'; then
        echo "  would change: $u (current shell: $CURSHELL)"
      fi
    fi
  done
fi

# --- (6) Optional extras: nftables rate limit (only if no UFW/firewalld) ---
if [ "${SWITCH_PORT:-0}" -eq 1 ]; then
  ACTIVE_PORT="${SSH_PORT:-2222}"
else
  ACTIVE_PORT="22"
fi

if [ $NFT_PRESENT -eq 1 ] && [ $UFW_ACTIVE -eq 0 ] && [ $FWD_ACTIVE -eq 0 ]; then
  log "Adding nftables SSH rate limit (safe default) on tcp dport $ACTIVE_PORT…"
  nft list ruleset | grep -q 'table inet filter' || nft add table inet filter
  nft list table inet filter 2>/dev/null | grep -q 'chain input' || nft add chain inet filter input "{ type filter hook input priority 0 ; policy accept ; }"
  # Only add if a similar rule not present
  if ! nft list chain inet filter input 2>/dev/null | grep -q "tcp dport $ACTIVE_PORT .* ct state new .* limit rate over 30/minute .* drop"; then
    nft add rule inet filter input tcp dport "$ACTIVE_PORT" ct state new limit rate over 30/minute drop || warn "Could not add nft limit rule."
  fi
else
  log "Skipping nftables rate-limit (either nft not present or UFW/firewalld active)."
fi

log "Done. Keep your current SSH session open and test a NEW connection before logging out."
if [ "${SWITCH_PORT:-0}" -eq 1 ]; then
  echo "Test: ssh -p ${SSH_PORT:-2222} ${ADMIN}@<server-ip>"
  echo "Firewall left to also allow 22 for safety; you can close it after you confirm new port works."
fi
