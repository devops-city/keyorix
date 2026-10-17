#!/usr/bin/env bash
# install.sh -- install (or re-apply) the hosted Keyorix demo on ONE fresh Ubuntu/Debian VM
# (DEMO-HOSTED-1, phase 1: a private link used during scheduled calls).
#
#   sudo deploy/demo-hosted/install.sh --hostname demo.example.com --acme-email you@example.com \
#        --ssh-allow 203.0.113.7/32 [--allow-ip 198.51.100.0/24] [--gate basic|ip|both|none]
#
# Run it from a checkout of the repository at a RELEASE TAG (the compose file pins the
# images of that release). It is idempotent: re-running re-applies the whole setup, never
# regenerates an existing secret, and takes its defaults from the previous run's
# /etc/keyorix-demo/demo.env, so `sudo deploy/demo-hosted/install.sh --idle-minutes 90`
# changes only that.
#
# Needs from you: a VM, a DNS A record for --hostname pointing at it (see the README),
# and an e-mail address for Let's Encrypt. No cloud credential, token or DNS API key
# is ever used or asked for.
#
# Options
#   --hostname FQDN          public name of the demo (required first time)
#   --acme-email ADDRESS     Let's Encrypt contact (required first time)
#   --acme-ca staging|production   staging rehearses without production rate limits (default production)
#   --gate basic|ip|both|none      what stands in front of the login page (default basic):
#                            basic = HTTP basic auth, user "demo", generated password in
#                                    <state>/gate_password;  ip = only --allow-ip addresses;
#                            both = both;  none = open to the internet (not for phase 1)
#   --allow-ip CIDR[,CIDR]   addresses allowed through the gate (required for ip/both)
#   --ssh-allow CIDR[,CIDR]|any   who may reach port 22 (required unless --no-firewall)
#   --no-firewall            do not touch ufw (you manage the cloud firewall)
#   --harden-ssh             key-only root login, no passwords (refuses if no authorized key exists)
#   --idle-action stop|poweroff|none   after --idle-minutes without use (default poweroff)
#   --idle-minutes N         default 45;  --grace-minutes N  default 30
#   --reset-time HH:MM       nightly reset, UTC (default 03:30)
#   --seed-script REPO/PATH  seed/scenario script to run after every reset (repeatable, in order;
#                            DEMO-LOCAL-2's scripts, repo-relative). None = PLACEHOLDER hook.
#   --require-seed           a reset fails when no seed script is configured
#   --no-start               install but do not start the stack
#   --render-only            write config, secrets and the gate under --state-dir/--conf-dir
#                            and stop: no packages, users, firewall, units or containers
#                            (used by the offline tests and for a dry look)
#   --state-dir DIR          default /var/lib/keyorix-demo
#   --conf-dir DIR           default /etc/keyorix-demo
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$KIT_DIR/../.." && pwd)"

SERVER_UID=1001                # the keyorix-server image's user (docker-compose.yml comments)
SERVICE_USER=keyorix-demo
GATE_USER=demo
ACME_PRODUCTION=https://acme-v02.api.letsencrypt.org/directory
ACME_STAGING=https://acme-staging-v02.api.letsencrypt.org/directory
MIN_COMPOSE=2.24.4             # `!override` in docker-compose.demo.yml

log() { printf 'install: %s\n' "$*"; }
warn() { printf 'install: WARNING: %s\n' "$*" >&2; }
die() { printf 'install: ERROR: %s\n' "$*" >&2; exit 1; }

STATE_DIR=/var/lib/keyorix-demo
CONF_DIR=/etc/keyorix-demo
RENDER_ONLY=0
NO_START=0
HARDEN_SSH=0

# --- defaults from a previous run -----------------------------------------------------
prev_value() { # KEY -> value from the previous demo.env, empty if none
  local f="$CONF_DIR/demo.env"
  [ -f "$f" ] || return 0
  grep -E "^$1=" "$f" | tail -n 1 | cut -d= -f2- || true
}
# --state-dir/--conf-dir must be known before the defaults are read.
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case ${args[i]} in
    --state-dir) STATE_DIR=${args[i + 1]:-} ;;
    --conf-dir) CONF_DIR=${args[i + 1]:-} ;;
  esac
done

DOMAIN=$(prev_value KEYORIX_DOMAIN)
ACME_EMAIL=$(prev_value KEYORIX_ACME_EMAIL)
ACME_CA=$(prev_value KEYORIX_ACME_CA); ACME_CA=${ACME_CA:-$ACME_PRODUCTION}
GATE=$(prev_value KEYORIX_DEMO_GATE); GATE=${GATE:-basic}
ALLOW_IP=$(prev_value KEYORIX_DEMO_ALLOW_IP)
SSH_ALLOW=$(prev_value KEYORIX_DEMO_SSH_ALLOW)
FIREWALL=$(prev_value KEYORIX_DEMO_FIREWALL); FIREWALL=${FIREWALL:-manage}
IDLE_ACTION=$(prev_value KEYORIX_DEMO_IDLE_ACTION); IDLE_ACTION=${IDLE_ACTION:-poweroff}
IDLE_MINUTES=$(prev_value KEYORIX_DEMO_IDLE_MINUTES); IDLE_MINUTES=${IDLE_MINUTES:-45}
GRACE_MINUTES=$(prev_value KEYORIX_DEMO_GRACE_MINUTES); GRACE_MINUTES=${GRACE_MINUTES:-30}
RESET_TIME=$(prev_value KEYORIX_DEMO_RESET_TIME); RESET_TIME=${RESET_TIME:-03:30}
SEED_SCRIPTS=$(prev_value KEYORIX_DEMO_SEED_SCRIPTS)
REQUIRE_SEED=$(prev_value KEYORIX_DEMO_REQUIRE_SEED); REQUIRE_SEED=${REQUIRE_SEED:-0}

SEED_GIVEN=0
while [ $# -gt 0 ]; do
  case $1 in
    --hostname) DOMAIN=${2:-}; shift 2 ;;
    --acme-email) ACME_EMAIL=${2:-}; shift 2 ;;
    --acme-ca)
      case ${2:-} in
        staging) ACME_CA=$ACME_STAGING ;;
        production) ACME_CA=$ACME_PRODUCTION ;;
        *) die "--acme-ca must be staging or production" ;;
      esac
      shift 2 ;;
    --gate) GATE=${2:-}; shift 2 ;;
    --allow-ip) ALLOW_IP=${2:-}; shift 2 ;;
    --ssh-allow) SSH_ALLOW=${2:-}; FIREWALL=manage; shift 2 ;;
    --no-firewall) FIREWALL=skip; shift ;;
    --harden-ssh) HARDEN_SSH=1; shift ;;
    --idle-action) IDLE_ACTION=${2:-}; shift 2 ;;
    --idle-minutes) IDLE_MINUTES=${2:-}; shift 2 ;;
    --grace-minutes) GRACE_MINUTES=${2:-}; shift 2 ;;
    --reset-time) RESET_TIME=${2:-}; shift 2 ;;
    --seed-script)
      if [ "$SEED_GIVEN" = 0 ]; then SEED_SCRIPTS=""; SEED_GIVEN=1; fi
      SEED_SCRIPTS="${SEED_SCRIPTS:+$SEED_SCRIPTS }${2:-}"; shift 2 ;;
    --require-seed) REQUIRE_SEED=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --render-only) RENDER_ONLY=1; shift ;;
    --state-dir|--conf-dir) shift 2 ;; # read above
    -h|--help) sed -n '2,41p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

# --- validation: everything is checked before the first change is made ----------------
[[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]] \
  || die "--hostname must be a lower-case fully qualified name such as demo.example.com (got '$DOMAIN')"
[[ $ACME_EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] \
  || die "--acme-email must be an e-mail address (got '$ACME_EMAIL')"
case $GATE in basic|ip|both|none) ;; *) die "--gate must be basic, ip, both or none" ;; esac
case $IDLE_ACTION in stop|poweroff|none) ;; *) die "--idle-action must be stop, poweroff or none" ;; esac
[[ $IDLE_MINUTES =~ ^[0-9]+$ && $IDLE_MINUTES -ge 5 ]] || die "--idle-minutes must be a number >= 5"
[[ $GRACE_MINUTES =~ ^[0-9]+$ ]] || die "--grace-minutes must be a number"
[[ $RESET_TIME =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "--reset-time must be HH:MM (UTC)"
[[ $STATE_DIR == /?* && $CONF_DIR == /?* ]] || die "--state-dir and --conf-dir must be absolute paths"

check_cidrs() { # label list
  local c
  IFS=, read -r -a _cidrs <<<"$2"
  for c in "${_cidrs[@]}"; do
    [[ $c =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "$1: '$c' is not an address or CIDR"
  done
}
if [ "$GATE" = ip ] || [ "$GATE" = both ]; then
  [ -n "$ALLOW_IP" ] || die "--gate $GATE needs --allow-ip"
fi
[ -z "$ALLOW_IP" ] || check_cidrs --allow-ip "$ALLOW_IP"
if [ "$FIREWALL" = manage ] && [ "$RENDER_ONLY" = 0 ]; then
  [ -n "$SSH_ALLOW" ] || die "say who may reach SSH: --ssh-allow CIDR[,CIDR] (or 'any', or --no-firewall if the cloud firewall does it)"
  [ "$SSH_ALLOW" = any ] || check_cidrs --ssh-allow "$SSH_ALLOW"
fi
for rel in $SEED_SCRIPTS; do
  case $rel in /*|*..*) die "--seed-script must be a repo-relative path without '..': $rel" ;; esac
  [ -x "$REPO_DIR/$rel" ] || die "--seed-script $rel is not an executable file in $REPO_DIR"
done
for f in docker-compose.yml keyorix.docker.yaml scripts/selfhost/init-secrets.sh \
         deploy/demo-hosted/docker-compose.demo.yml deploy/demo-hosted/Caddyfile.demo; do
  [ -f "$REPO_DIR/$f" ] || die "$REPO_DIR/$f is missing: run this from a complete checkout of the repository"
done

SECRETS_DIR="$STATE_DIR/secrets"
GATE_DIR="$STATE_DIR/gate"
CONFIG_OUT="$STATE_DIR/keyorix.demo.yaml"
ENV_FILE="$CONF_DIR/demo.env"

if [ "$RENDER_ONLY" = 0 ]; then
  [ "$(id -u)" = 0 ] || die "run as root (sudo)"
  [ -r /etc/os-release ] || die "unsupported OS (no /etc/os-release)"
  # shellcheck source=/dev/null
  . /etc/os-release
  case ${ID:-} in ubuntu|debian) ;; *) die "supported: Ubuntu or Debian (this is '${ID:-unknown}'). Install Docker Engine + Compose >= $MIN_COMPOSE yourself and use --render-only for the files." ;; esac
fi

random_token() { openssl rand -base64 36 | tr -d '/+=\n'; }

# --- packages and Docker ---------------------------------------------------------------
compose_ok() {
  local v
  v=$(docker compose version --short 2>/dev/null) || return 1
  v=${v#v}
  [ "$(printf '%s\n%s\n' "$MIN_COMPOSE" "$v" | sort -V | head -n 1)" = "$MIN_COMPOSE" ]
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg openssl apache2-utils util-linux unattended-upgrades
  if [ "$FIREWALL" = manage ]; then apt-get install -y -qq ufw; fi
  if ! compose_ok; then
    log "installing Docker Engine from Docker's apt repository (Compose >= $MIN_COMPOSE needed)"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
      "$(dpkg --print-architecture)" "$ID" "$VERSION_CODENAME" >/etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  fi
  systemctl enable --now docker
  compose_ok || die "Docker Compose >= $MIN_COMPOSE is required and could not be installed"
}

check_dns() {
  local resolved local_ips
  resolved=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
  local_ips=$(hostname -I 2>/dev/null || true)
  if [ -z "$resolved" ]; then
    warn "$DOMAIN does not resolve yet. Create the A record first (README), or Let's Encrypt cannot issue the certificate."
    return 0
  fi
  case " $local_ips " in
    *" ${resolved%% *} "*) log "DNS: $DOMAIN -> ${resolved% } (this VM)" ;;
    *) warn "$DOMAIN resolves to ${resolved% }, which is not an address of this VM ($local_ips). Behind NAT or a floating IP that can be fine; otherwise fix the A record." ;;
  esac
}

# --- users, directories ------------------------------------------------------------------
setup_dirs() {
  if [ "$RENDER_ONLY" = 0 ]; then
    id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
    install -d -m 0755 "$CONF_DIR"
  else
    mkdir -p "$STATE_DIR" "$CONF_DIR"
    chmod 750 "$STATE_DIR"
  fi
  mkdir -p "$GATE_DIR"
  chmod 755 "$GATE_DIR"
}

as_service_user() { # run a command as the service user (the current user when rendering)
  if [ "$RENDER_ONLY" = 0 ]; then runuser -u "$SERVICE_USER" -- "$@"; else "$@"; fi
}

# --- the server config: the shipped one plus the strict audit level ---------------------------
render_config() {
  local base="$REPO_DIR/keyorix.docker.yaml"
  if grep -Eq '^[[:space:]]+audit_durability:' "$base"; then
    die "$base already sets audit_durability; update render_config in install.sh"
  fi
  awk '
    /^storage:/ { in_storage = 1; print; next }
    in_storage && /^[^[:space:]#]/ { in_storage = 0 }
    in_storage && /^  database:[[:space:]]*$/ {
      print
      print "    # DEMO-HOSTED-1 (docs/security/hardening-guide.md 5a): every disclosed secret has an"
      print "    # audit record that is on disk before the secret is returned."
      print "    audit_durability: strict"
      done = 1
      next
    }
    { print }
    END { if (!done) exit 3 }
  ' "$base" >"$CONFIG_OUT.new" || { rm -f "$CONFIG_OUT.new"; die "no storage.database block found in $base; update render_config in install.sh"; }
  chmod 644 "$CONFIG_OUT.new"
  mv -f "$CONFIG_OUT.new" "$CONFIG_OUT"
  log "wrote $CONFIG_OUT (shipped config + audit_durability: strict)"
}

# --- secrets: the production path (init-secrets.sh), then the bootstrap token -----------------
secrets_complete() {
  local n
  for n in db_password master_password admin_password bootstrap_token postgres_tls.crt postgres_tls.key; do
    [ -e "$SECRETS_DIR/$n" ] || return 1
  done
}

make_secrets() {
  if secrets_complete; then
    log "secrets: all present, kept"
  else
    # A hardened token is owned by the server uid, which init-secrets.sh refuses; it is
    # only used for the first bootstrap, so drop it here and let it be generated again.
    rm -f "$SECRETS_DIR/bootstrap_token"
    as_service_user env KEYORIX_SECRETS_DIR="$SECRETS_DIR" \
      sh "$REPO_DIR/scripts/selfhost/init-secrets.sh" --dir "$SECRETS_DIR" --env-file "$STATE_DIR/init-secrets.env" >/dev/null \
      || die "scripts/selfhost/init-secrets.sh failed (run it by hand for its message)"
    log "secrets: generated under $SECRETS_DIR (the master password is this VM's own KEK secret; it is never printed)"
  fi
  harden_bootstrap_token
}

# The bootstrap token is a fresh >= 32 character random value in a 0600 file owned by the
# server's uid (so the container reads it without any group access), not the 0640 one
# init-secrets.sh makes.
harden_bootstrap_token() {
  local f="$SECRETS_DIR/bootstrap_token" len=0
  if [ -f "$f" ]; then len=$(tr -d '\n' <"$f" | wc -c | tr -d ' '); fi
  if [ "$len" -lt 32 ]; then
    ( umask 077; openssl rand -hex 32 >"$f.new" )
    mv -f "$f.new" "$f"
    log "bootstrap token: generated (64 characters)"
  fi
  chmod 600 "$f"
  if [ "$(id -u)" = 0 ]; then
    chown "$SERVER_UID:$SERVER_UID" "$f"
  else
    warn "not root: $f stays owned by you (a real install chowns it to uid $SERVER_UID)"
  fi
}

# --- the gate in front of the login page ----------------------------------------------------------
write_gate() {
  local out="$GATE_DIR/gate.caddy" hash cidrs
  {
    echo "# Generated by deploy/demo-hosted/install.sh (gate: $GATE). Re-run install.sh to change it."
    if [ "$GATE" = ip ] || [ "$GATE" = both ]; then
      cidrs=${ALLOW_IP//,/ }
      echo "@not_allowed not remote_ip $cidrs"
      echo 'respond @not_allowed "Forbidden" 403'
    fi
    if [ "$GATE" = basic ] || [ "$GATE" = both ]; then
      hash=$(gate_hash)
      echo "basic_auth {"
      printf '\t%s %s\n' "$GATE_USER" "$hash"
      echo "}"
    fi
    if [ "$GATE" = none ]; then
      echo "# gate none: the demo is open to the whole internet"
    fi
  } >"$out.new"
  chmod 644 "$out.new"
  mv -f "$out.new" "$out"
  if [ "$RENDER_ONLY" = 0 ]; then chown -R root:root "$GATE_DIR"; fi
  log "gate: $GATE (written to $out)"
}

gate_hash() { # bcrypt hash of the generated password; generated once, reused
  local pw="$STATE_DIR/gate_password" hf="$STATE_DIR/gate_hash"
  if [ ! -s "$pw" ]; then
    ( umask 077; random_token >"$pw" )
    rm -f "$hf"
  fi
  if [ ! -s "$hf" ]; then
    command -v htpasswd >/dev/null || die "htpasswd is missing (apt install apache2-utils)"
    ( umask 077; htpasswd -niBC 10 "$GATE_USER" <"$pw" | cut -d: -f2- | tr -d '\n' >"$hf.new" )
    mv -f "$hf.new" "$hf"
  fi
  cat "$hf"
}

# --- compose environment (no secret values in it) --------------------------------------------------
write_env() {
  local gid
  gid=$(grep -E '^KEYORIX_SECRETS_GID=' "$STATE_DIR/init-secrets.env" | tail -n 1 | cut -d= -f2-)
  [[ $gid =~ ^[0-9]+$ ]] || die "KEYORIX_SECRETS_GID missing from $STATE_DIR/init-secrets.env"
  {
    echo "# Generated by deploy/demo-hosted/install.sh. No secret values in this file."
    echo "KEYORIX_DOMAIN=$DOMAIN"
    echo "KEYORIX_ACME_EMAIL=$ACME_EMAIL"
    echo "KEYORIX_ACME_CA=$ACME_CA"
    echo "KEYORIX_SECRETS_DIR=$SECRETS_DIR"
    echo "KEYORIX_SECRETS_GID=$gid"
    echo "KEYORIX_DEMO_CONFIG=$CONFIG_OUT"
    echo "KEYORIX_DEMO_GATE_DIR=$GATE_DIR"
    echo "KEYORIX_DEMO_REPO=$REPO_DIR"
    echo "KEYORIX_DEMO_STATE=$STATE_DIR"
    echo "KEYORIX_DEMO_GATE=$GATE"
    echo "KEYORIX_DEMO_ALLOW_IP=$ALLOW_IP"
    echo "KEYORIX_DEMO_SSH_ALLOW=$SSH_ALLOW"
    echo "KEYORIX_DEMO_FIREWALL=$FIREWALL"
    echo "KEYORIX_DEMO_IDLE_ACTION=$IDLE_ACTION"
    echo "KEYORIX_DEMO_IDLE_MINUTES=$IDLE_MINUTES"
    echo "KEYORIX_DEMO_GRACE_MINUTES=$GRACE_MINUTES"
    echo "KEYORIX_DEMO_RESET_TIME=$RESET_TIME"
    echo "KEYORIX_DEMO_SEED_SCRIPTS=$SEED_SCRIPTS"
    echo "KEYORIX_DEMO_REQUIRE_SEED=$REQUIRE_SEED"
  } >"$ENV_FILE.new"
  chmod 644 "$ENV_FILE.new"
  mv -f "$ENV_FILE.new" "$ENV_FILE"
  log "wrote $ENV_FILE"
}

# --- host: control script, units, firewall, ssh --------------------------------------------------------
install_units() {
  install -m 0755 "$KIT_DIR/democtl.sh" /usr/local/sbin/keyorix-demo
  local u
  for u in keyorix-demo.service keyorix-demo-reset.service keyorix-demo-reset.timer \
           keyorix-demo-idle.service keyorix-demo-idle.timer; do
    install -m 0644 "$KIT_DIR/systemd/$u" "/etc/systemd/system/$u"
  done
  install -d -m 0755 /etc/systemd/system/keyorix-demo-reset.timer.d
  printf '[Timer]\nOnCalendar=\nOnCalendar=*-*-* %s:00 UTC\n' "$RESET_TIME" \
    >/etc/systemd/system/keyorix-demo-reset.timer.d/schedule.conf
  systemctl daemon-reload
  systemctl enable keyorix-demo.service
  systemctl enable --now keyorix-demo-reset.timer keyorix-demo-idle.timer
  log "units: nightly reset at $RESET_TIME UTC; idle check every 5 minutes ($IDLE_ACTION after $IDLE_MINUTES minutes)"
}

setup_firewall() {
  local c
  if [ "$FIREWALL" != manage ]; then log "firewall: left alone (--no-firewall)"; return 0; fi
  # Deterministic: rebuilt from scratch every run. `reset` disables ufw first, so there is
  # no moment with a closed SSH port; the rules below are enabled again at the end.
  ufw --force reset >/dev/null
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  if [ "$SSH_ALLOW" = any ]; then
    ufw allow 22/tcp >/dev/null
  else
    IFS=, read -r -a _ssh <<<"$SSH_ALLOW"
    for c in "${_ssh[@]}"; do ufw allow from "$c" to any port 22 proto tcp >/dev/null; done
  fi
  ufw --force enable >/dev/null
  log "firewall: ufw allows 80, 443 and SSH from $SSH_ALLOW; everything else inbound is denied"
}

harden_ssh() {
  local keys=0 u home
  for u in root "${SUDO_USER:-}"; do
    [ -n "$u" ] || continue
    home=$(getent passwd "$u" | cut -d: -f6)
    if [ -s "$home/.ssh/authorized_keys" ]; then keys=1; fi
  done
  [ "$keys" = 1 ] || die "--harden-ssh refused: neither root nor \$SUDO_USER has an authorized key, you would lock yourself out"
  grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
    || die "--harden-ssh: sshd_config has no Include for sshd_config.d; configure PasswordAuthentication no by hand"
  install -d -m 0755 /etc/ssh/sshd_config.d
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' \
    >/etc/ssh/sshd_config.d/00-keyorix-demo.conf
  sshd -t || { rm -f /etc/ssh/sshd_config.d/00-keyorix-demo.conf; die "sshd rejected the hardening drop-in; removed it"; }
  systemctl reload ssh 2>/dev/null || systemctl reload sshd
  log "ssh: key-only (existing sessions stay open; test a NEW session before closing this one)"
}

# --- main -----------------------------------------------------------------------------------------
if [ "$RENDER_ONLY" = 0 ]; then
  install_packages
  check_dns
fi
setup_dirs
render_config
make_secrets
write_gate
write_env

if [ "$RENDER_ONLY" = 1 ]; then
  log "render-only: stopped before packages, units, firewall and containers"
  exit 0
fi

install_units
setup_firewall
if [ "$HARDEN_SSH" = 1 ]; then harden_ssh; fi

if [ "$NO_START" = 1 ]; then
  log "not starting (--no-start). Start with: sudo keyorix-demo up"
else
  /usr/local/sbin/keyorix-demo up
  log "seeding and the first full reset: sudo keyorix-demo reset  (also what the nightly timer runs)"
fi

cat <<EOF

Done. Demo URL: https://$DOMAIN   (the certificate is issued on the first request once DNS points here)
  gate:            $GATE   (basic auth user: $GATE_USER, password file: $STATE_DIR/gate_password)
  first admin:     user ${KEYORIX_ADMIN_USERNAME:-admin}, password file: $SECRETS_DIR/admin_password
  day-2 commands:  sudo keyorix-demo status | reset | down | up | destroy --yes
EOF
