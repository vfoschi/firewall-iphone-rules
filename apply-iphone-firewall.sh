#!/usr/bin/env bash
# =============================================================================
# apply-iphone-firewall.sh
# Applica regole iptables minime per iPhone su rete Wi-Fi aziendale
# Scenari coperti: Wi-Fi Calling, Microsoft 365, Google Auth, Okta, Auth0
#
# PREREQUISITI:
#   - iptables installato (apt install iptables / yum install iptables)
#   - ipset installato per gestione CIDR Apple (apt install ipset)
#   - Esecuzione come root (sudo)
#   - iptables-persistent per rendere le regole permanenti (opzionale)
#
# ATTENZIONE: lo script sostituisce le regole esistenti della chain OUTPUT.
#             Verificare che non ci siano regole critiche preesistenti.
#
# USO:
#   sudo bash apply-iphone-firewall.sh [--dry-run] [--no-persist]
#   --dry-run   : mostra i comandi senza eseguirli
#   --no-persist: non salva le regole (default: salva con iptables-save)
# =============================================================================

set -euo pipefail

# --- Variabili configurabili -------------------------------------------------
AUTH0_TENANT="YOUR_TENANT"          # es. mycompany -> mycompany.auth0.com
AUTH0_REGION="eu"                   # us | eu | au
CUSTOM_DOMAIN=""                    # es. login.azienda.it (lasciare vuoto se non usato)
IFACE=""                            # interfaccia di rete (vuoto = tutte, es. "eth0", "wlan0")
LOG_PREFIX="[FW-IPHONE] "
PERSIST_FILE="/etc/iptables/rules.v4"

# --- Flags -------------------------------------------------------------------
DRY_RUN=false
NO_PERSIST=false

for arg in "$@"; do
  case $arg in
    --dry-run) DRY_RUN=true ;;
    --no-persist) NO_PERSIST=true ;;
  esac
done

# --- Funzioni ----------------------------------------------------------------
ipt() {
  if $DRY_RUN; then
    echo "[DRY-RUN] iptables $*"
  else
    iptables "$@"
  fi
}

ipset_cmd() {
  if $DRY_RUN; then
    echo "[DRY-RUN] ipset $*"
  else
    ipset "$@" 2>/dev/null || true
  fi
}

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

require_root() {
  if [[ $EUID -ne 0 ]] && ! $DRY_RUN; then
    echo "ERRORE: questo script richiede privilegi root (sudo)." >&2
    exit 1
  fi
}

# Costruisce opzione -o se IFACE e' definita
iface_opt() {
  if [[ -n "$IFACE" ]]; then echo "-o $IFACE"; else echo ""; fi
}

# --- Funzione: consenti FQDN su porta TCP ------------------------------------
# iptables non supporta FQDN nativamente; usiamo la risoluzione DNS al momento
# dell'applicazione. Per ambienti dinamici considerare iptables-dns o un proxy.
allow_fqdn_tcp() {
  local port="$1"
  shift
  local fqdns=("$@")
  for fqdn in "${fqdns[@]}"; do
    # Risolve il FQDN e aggiunge una regola per ogni IP
    local ips
    ips=$(getent ahostsv4 "$fqdn" 2>/dev/null | awk '{print $1}' | sort -u)
    if [[ -z "$ips" ]]; then
      log "WARN: impossibile risolvere $fqdn - regola saltata"
      continue
    fi
    for ip in $ips; do
      ipt -A OUTPUT $(iface_opt) -p tcp -d "$ip" --dport "$port" -j ACCEPT \
        -m comment --comment "FQDN:$fqdn"
    done
  done
}

allow_fqdn_http() {
  allow_fqdn_tcp 80 "$@"
}

allow_fqdn_https() {
  allow_fqdn_tcp 443 "$@"
}

# =============================================================================
# MAIN
# =============================================================================
require_root
log "=== Avvio applicazione regole firewall iPhone ==="
$DRY_RUN && log "MODALITA DRY-RUN: nessuna modifica verra applicata"

# --- Step 1: Flush OUTPUT chain e imposta policy DROP ------------------------
log "--- Step 1: Reset chain OUTPUT ---"
ipt -F OUTPUT
ipt -P OUTPUT DROP

# --- Step 2: Consenti traffico loopback --------------------------------------
log "--- Step 2: Loopback ---"
ipt -A OUTPUT -o lo -j ACCEPT

# --- Step 3: Consenti traffico ESTABLISHED/RELATED (risposte) ----------------
log "--- Step 3: Connessioni established/related ---"
ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# =============================================================================
# SEZIONE BASE: DNS, NTP, APNs, Wi-Fi Calling, Microsoft 365
# =============================================================================

# --- RULE-001/002: DNS -------------------------------------------------------
log "--- RULE-001/002: DNS (UDP+TCP/53) ---"
ipt -A OUTPUT $(iface_opt) -p udp --dport 53 -j ACCEPT \
  -m comment --comment "RULE-001: DNS UDP"
ipt -A OUTPUT $(iface_opt) -p tcp --dport 53 -j ACCEPT \
  -m comment --comment "RULE-002: DNS TCP"

# --- RULE-003: NTP -----------------------------------------------------------
log "--- RULE-003: NTP (UDP/123) ---"
ipt -A OUTPUT $(iface_opt) -p udp --dport 123 -j ACCEPT \
  -m comment --comment "RULE-003: NTP"

# --- RULE-010/011/012: Apple APNs (17.0.0.0/8) ------------------------------
log "--- RULE-010/011/012: Apple APNs (17.0.0.0/8) ---"
# Crea ipset per il blocco Apple se non esiste
ipset_cmd create apple-net hash:net 2>/dev/null || true
ipset_cmd add apple-net 17.0.0.0/8 2>/dev/null || true

if $DRY_RUN; then
  echo "[DRY-RUN] ipset create apple-net hash:net"
  echo "[DRY-RUN] ipset add apple-net 17.0.0.0/8"
fi

ipt -A OUTPUT $(iface_opt) -p tcp --dport 5223 \
  -m set --match-set apple-net dst -j ACCEPT \
  -m comment --comment "RULE-010: APNs TCP/5223"
ipt -A OUTPUT $(iface_opt) -p tcp --dport 443 \
  -m set --match-set apple-net dst -j ACCEPT \
  -m comment --comment "RULE-011: APNs TCP/443 fallback"
ipt -A OUTPUT $(iface_opt) -p tcp --dport 2197 \
  -m set --match-set apple-net dst -j ACCEPT \
  -m comment --comment "RULE-012: APNs TCP/2197 alt"

# --- RULE-020/021: Wi-Fi Calling (IKEv2 + IPsec NAT-T) ----------------------
log "--- RULE-020/021: Wi-Fi Calling (UDP/500, UDP/4500) ---"
ipt -A OUTPUT $(iface_opt) -p udp --dport 500 -j ACCEPT \
  -m comment --comment "RULE-020: WiFi Calling IKEv2"
ipt -A OUTPUT $(iface_opt) -p udp --dport 4500 -j ACCEPT \
  -m comment --comment "RULE-021: WiFi Calling IPsec NAT-T"

# --- RULE-030: Microsoft Entra ID autenticazione primaria --------------------
log "--- RULE-030: Microsoft Entra ID auth ---"
allow_fqdn_https \
  "login.microsoftonline.com" \
  "login.microsoft.com" \
  "login.windows.net" \
  "sts.windows.net" \
  "login.live.com"

# --- RULE-031: Microsoft 365 CDN autenticazione ------------------------------
log "--- RULE-031: Microsoft 365 auth CDN ---"
allow_fqdn_https \
  "aadcdn.msftauth.net" \
  "aadcdn.msauth.net" \
  "secure.aadcdn.microsoftonline-p.com" \
  "account.live.com"

# --- RULE-032: Microsoft Graph API -------------------------------------------
log "--- RULE-032: Microsoft Graph ---"
allow_fqdn_https \
  "graph.microsoft.com" \
  "management.azure.com"

# --- RULE-033: Microsoft MFA wildcard ----------------------------------------
log "--- RULE-033: Microsoft MFA (microsoftonline.com) ---"
# Per i wildcard usiamo i principali FQDN concreti
allow_fqdn_https \
  "autologon.microsoftazuread-sso.com" \
  "clientconfig.microsoftonline-p.net" \
  "mobileappauth.microsoft.com"

# --- RULE-040/041: CRL e OCSP Microsoft/DigiCert ----------------------------
log "--- RULE-040/041: CRL/OCSP Microsoft ---"
allow_fqdn_http \
  "ocsp.digicert.com" \
  "ocsp.msocsp.com" \
  "oneocsp.microsoft.com" \
  "crl.microsoft.com" \
  "crl3.digicert.com" \
  "crl4.digicert.com" \
  "mscrl.microsoft.com"

# =============================================================================
# SEZIONE GOOGLE AUTH
# =============================================================================
log "=== SEZIONE GOOGLE AUTH ==="

# --- GOOG-001/002/003/004/005: Google OAuth2/OIDC ----------------------------
log "--- GOOG-001..005: Google OAuth2/OIDC/Assets ---"
allow_fqdn_https \
  "accounts.google.com" \
  "accounts.google.it" \
  "oauth2.googleapis.com" \
  "www.googleapis.com" \
  "openidconnect.googleapis.com" \
  "ssl.gstatic.com" \
  "www.gstatic.com" \
  "fonts.gstatic.com" \
  "fonts.googleapis.com" \
  "people.googleapis.com"

# --- GOOG-010: Google Authenticator / Google APIs wildcard -------------------
log "--- GOOG-010: Google APIs (googleapis.com) ---"
# Risolviamo i principali endpoint invece del wildcard
allow_fqdn_https \
  "lh3.googleapis.com" \
  "www.googleapis.com" \
  "content.googleapis.com" \
  "storage.googleapis.com"

# --- GOOG-020/021: Google PKI CRL/OCSP (HTTP/80) ----------------------------
log "--- GOOG-020/021: Google PKI CRL/OCSP ---"
allow_fqdn_http \
  "crl.pki.goog" \
  "crls.pki.goog" \
  "c.pki.goog" \
  "ocsp.pki.goog"

# =============================================================================
# SEZIONE OKTA
# =============================================================================
log "=== SEZIONE OKTA ==="

# --- OKTA-001/002: Okta tenant e EMEA ----------------------------------------
log "--- OKTA-001/002: Okta tenant (okta.com + okta-emea.com) ---"
allow_fqdn_https \
  "okta.com" \
  "ok12static.oktacdn.com"
# Nota: *.okta.com e *.okta-emea.com non si risolvono come wildcard via getent.
# Aggiungere qui il FQDN concreto del proprio tenant:
# es. "mycompany.okta.com" "mycompany.okta-emea.com"
log "ATTENZIONE: aggiungere il FQDN del proprio tenant Okta (es. mycompany.okta.com)"

# --- OKTA-003: Okta CDN ------------------------------------------------------
log "--- OKTA-003: Okta CDN ---"
allow_fqdn_https \
  "global.oktacdn.com" \
  "op1static.oktacdn.com" \
  "ok12static.oktacdn.com"

# --- OKTA-006: AWS Global Accelerator ----------------------------------------
log "--- OKTA-006: AWS Global Accelerator ---"
allow_fqdn_https \
  "anycast.awsglobalaccelerator.com"

# --- OKTA-010: Okta CRL/OCSP -------------------------------------------------
log "--- OKTA-010: Okta CRL/OCSP (DigiCert) ---"
allow_fqdn_http \
  "ocsp.digicert.com" \
  "crl3.digicert.com" \
  "crl4.digicert.com"

# =============================================================================
# SEZIONE AUTH0
# =============================================================================
log "=== SEZIONE AUTH0 ==="

# --- AUTH0-001: Auth0 tenant principale --------------------------------------
log "--- AUTH0-001: Auth0 tenant ($AUTH0_TENANT) ---"
if [[ "$AUTH0_TENANT" == "YOUR_TENANT" ]]; then
  log "WARN: AUTH0_TENANT non configurato. Modifica la variabile in cima allo script."
else
  case "$AUTH0_REGION" in
    us) AUTH0_FQDN="${AUTH0_TENANT}.auth0.com" ;;
    eu) AUTH0_FQDN="${AUTH0_TENANT}.eu.auth0.com" ;;
    au) AUTH0_FQDN="${AUTH0_TENANT}.au.auth0.com" ;;
    *)  AUTH0_FQDN="${AUTH0_TENANT}.auth0.com" ;;
  esac
  allow_fqdn_https "$AUTH0_FQDN"
fi

# --- AUTH0-002: Auth0 CDN ----------------------------------------------------
log "--- AUTH0-002: Auth0 CDN ---"
case "$AUTH0_REGION" in
  eu) allow_fqdn_https "cdn.eu.auth0.com" ;;
  au) allow_fqdn_https "cdn.au.auth0.com" ;;
  *)  allow_fqdn_https "cdn.auth0.com" ;;
esac

# --- AUTH0-003: Auth0 custom domain (opzionale) ------------------------------
if [[ -n "$CUSTOM_DOMAIN" ]]; then
  log "--- AUTH0-003: Auth0 custom domain ($CUSTOM_DOMAIN) ---"
  allow_fqdn_https "$CUSTOM_DOMAIN"
fi

# --- AUTH0-005: Auth0 Guardian MFA -------------------------------------------
log "--- AUTH0-005: Auth0 Guardian ---"
allow_fqdn_https "guardian.auth0.com" "guardian.eu.auth0.com"

# --- AUTH0-010: Auth0 CRL/OCSP -----------------------------------------------
log "--- AUTH0-010: Auth0 CRL/OCSP ---"
allow_fqdn_http \
  "ocsp.digicert.com" \
  "crl3.digicert.com" \
  "crl4.digicert.com" \
  "r3.o.lencr.org"

# =============================================================================
# LOGGING: DROP finale con log
# =============================================================================
log "--- Regola di DROP finale con logging ---"
ipt -A OUTPUT $(iface_opt) -m limit --limit 5/min -j LOG \
  --log-prefix "${LOG_PREFIX}DROP " --log-level 4
ipt -A OUTPUT $(iface_opt) -j DROP

# =============================================================================
# PERSISTENZA
# =============================================================================
if ! $NO_PERSIST && ! $DRY_RUN; then
  log "--- Salvataggio regole ---"
  if command -v iptables-save &>/dev/null; then
    mkdir -p "$(dirname "$PERSIST_FILE")"
    iptables-save > "$PERSIST_FILE"
    log "Regole salvate in $PERSIST_FILE"
    log "Per caricarle al boot: apt install iptables-persistent (Debian/Ubuntu)"
    log "                   oppure: systemctl enable iptables (RHEL/CentOS)"
  else
    log "WARN: iptables-save non trovato. Le regole non sono persistenti."
  fi
fi

# =============================================================================
# RIEPILOGO
# =============================================================================
log "=== Applicazione completata ==="
if ! $DRY_RUN; then
  log "--- Regole OUTPUT attive ---"
  iptables -L OUTPUT -n -v --line-numbers
fi
log "Script terminato."
