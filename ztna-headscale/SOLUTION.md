# ZTNA Headscale — Soluzione Technacy/NETMON

## Sommario esecutivo

Soluzione ZTNA (Zero Trust Network Access) basata su **Headscale** (control plane
WireGuard open-source self-hosted) che estende la piattaforma NETMON con accesso
sicuro, trasparente e indipendente dal mezzo fisico (WiFi o SIM 4G/5G).

Il principio fondante: ogni dispositivo client — smartphone, laptop, IP camera —
ottiene lo stesso indirizzo IP privato overlay e la stessa esperienza di connettività
indipendentemente da dove si trova e da quale rete usa. WiFi e SIM NETMON diventano
**completamente trasparenti e intercambiabili**.

---

## Architettura

### Dual control plane

La soluzione prevede due istanze Headscale distinte e federate:

```
[Headscale NETMON]  <--OIDC/API peering-->  [Headscale Cliente]
  hs.netmon.it                                 hs.cliente.it
  (Infrastruttura Technacy)                    (On-premise/cloud cliente)
```

**Headscale NETMON** (gestito da Technacy):
- Control plane primario per tutti i dispositivi mobili (iPhone, laptop, IoT)
- Integrato con le API NETMON per verifica SIM, tenant e profilo di sicurezza
- Gestisce le ACL globali e l'identità degli utenti
- Endpoint pubblico: `hs.netmon.it` (o sottodominio per tenant)

**Headscale Cliente** (installato in rete cliente):
- Control plane locale per le risorse interne del cliente
- Gestisce exit node, subnet router e accesso alle risorse LAN
- Il traffico verso la rete cliente non transita su infrastruttura Technacy
- Endpoint: `hs.cliente.it` (può essere privato, raggiungibile solo via mesh)

### Data plane: WireGuard mesh

I dispositivi client eseguono **Tailscale** (client compatibile con Headscale).
Il tunnel WireGuard è stabilito **direttamente tra client e destinazione** (peer-to-peer
quando possibile, relay DERP quando NAT lo impedisce). Il control plane coordina
lo scambio di chiavi ma non vede il traffico dati.

```
iPhone (Tailscale)
  │
  ├── [via WiFi aziendale]  ──┐
  │                           ├──> WireGuard tunnel → Exit Node Cliente → LAN
  └── [via SIM NETMON 4G/5G] ─┘
                               stessa connettività, stesso IP overlay
```

---

## Componenti tecnici

### 1. Headscale NETMON (control plane primario)

| Parametro | Valore |
|---|---|
| Software | Headscale >= 0.23 |
| Deploy | Kubernetes (k3s Technacy) o VM dedicata |
| Dominio | `hs.netmon.it` |
| Porta | TCP 443 (HTTPS/gRPC) + UDP 3478 (STUN) |
| Database | PostgreSQL (HA) |
| Auth | OIDC → Microsoft Entra ID / Okta (già integrati NETMON) |
| API | REST + gRPC per integrazione NETMON tenant API |

**Funzioni chiave:**
- Registrazione e autenticazione dei dispositivi via OIDC
- Distribuzione delle chiavi WireGuard pubbliche
- Gestione delle ACL per policy di accesso granulare
- Coordinamento DERP relay per attraversamento NAT
- Webhook verso NETMON API: verifica che il dispositivo usi SIM attiva e
  profilo di sicurezza corretto (LIGHT / STANDARD / SECURED)

### 2. Headscale Cliente (control plane locale)

| Parametro | Valore |
|---|---|
| Software | Headscale >= 0.23 |
| Deploy | VM o container on-premise cliente / VPS dedicato |
| Requisiti HW | 1 vCPU, 512MB RAM, 10GB disco |
| Porta esposta | TCP 443 verso rete NETMON (non verso Internet pubblico) |
| Auth | Federato con Headscale NETMON via OIDC |

**Funzioni chiave:**
- Gestione delle subnet routes per la LAN cliente
- Configurazione exit node (tutto il traffico dei device esce dalla LAN cliente)
- Isolamento: il traffico dati verso la rete cliente non transita su Technacy
- Configurabile per split tunneling (solo traffico aziendale via mesh)

### 3. Client Tailscale sui dispositivi

| Dispositivo | Client | Note |
|---|---|---|
| iPhone / iPad | Tailscale iOS (App Store) | Multi-hop, split tunnel |
| Android | Tailscale Android | Identico a iOS |
| macOS / Windows | Tailscale desktop | App nativa |
| Linux / server | tailscaled | Daemon systemd |
| IP camera / IoT | tailscale (embedded) | Richiede Linux/OpenWRT |
| Router sede cliente | tailscale subnet router | Espone intera LAN senza agent su ogni device |

**Configurazione client iPhone:**
```
Server Headscale: https://hs.netmon.it
Auth: OIDC (Microsoft 365 / Okta — già in uso dai clienti NETMON)
Exit node: exit-node.cliente.it (IP overlay assegnato da Headscale Cliente)
Split tunnel: ON — solo traffico aziendale via mesh, resto diretto
```

### 4. Policy ACL (HuJSON)

Headscale usa un file ACL in formato HuJSON per definire le policy di accesso.
Esempio per scenario NETMON:

```json
{
  "groups": {
    "group:admin":    ["user:vittorio@technacy.it"],
    "group:clienteA": ["user:*@clienteA.it"],
    "group:iot":      ["tag:iot-cam"]
  },
  "tagOwners": {
    "tag:iot-cam": ["group:admin"]
  },
  "acls": [
    // Admin Technacy: accesso totale
    {"action":"accept","src":["group:admin"],"dst":["*:*"]},
    // Utenti cliente: accesso alla propria rete cliente
    {"action":"accept","src":["group:clienteA"],"dst":["10.100.0.0/24:*"]},
    // IoT: solo traffico verso backend NETMON (porta 8443)
    {"action":"accept","src":["tag:iot-cam"],"dst":["10.0.0.1:8443"]},
    // Default deny implicito
  ]
}
```

---

## Flusso di connessione (step by step)

### Scenario: iPhone su SIM NETMON accede a risorsa LAN cliente

```
1. iPhone avvia Tailscale
   → Contatta hs.netmon.it (Headscale NETMON) via SIM NETMON
   → Autenticazione OIDC (Microsoft 365 / Okta)
   → Headscale NETMON verifica SIM attiva tramite NETMON API
   → Headscale NETMON distribuisce chiave WireGuard pubblica dell'exit node cliente

2. Headscale NETMON notifica Headscale Cliente
   → "Dispositivo X autorizzato, può raggiungere exit node Y"
   → Headscale Cliente aggiorna la sua routing table overlay

3. iPhone stabilisce tunnel WireGuard diretto verso Exit Node Cliente
   → Pacchetti cifrati WireGuard su UDP
   → Attraversamento NAT via STUN (hs.netmon.it:3478)
   → Se NAT simmetrico: relay via DERP server (Technacy hosted)

4. iPhone cambia da SIM a WiFi (o viceversa)
   → WireGuard rileva cambio di endpoint (nuovo IP pubblico)
   → Riconnessione automatica in <1 secondo
   → Nessuna interruzione dell'applicazione, nessuna riautenticazione
   → L'IP overlay dell'iPhone (es. 100.64.0.5) rimane INVARIATO
```

### Scenario: IP camera su SIM NETMON invia stream a VMS cliente

```
1. IP camera (Linux embedded + Tailscale) si registra su hs.netmon.it
   → Tag: tag:iot-cam
   → ACL: può parlare solo con 10.100.0.0/24 (VLAN VMS)

2. Headscale NETMON valida SIM tramite NETMON API
   → Verifica profilo SECURED attivo sulla SIM
   → Se SIM sospesa o profilo degradato: revoca accesso mesh istantaneamente

3. Stream RTSP/ONVIF viaggia su tunnel WireGuard
   → Cifrato end-to-end (camera → VMS)
   → Nessuna porta aperta su firewall cliente
   → Failover automatico su altra SIM NETMON se segnale debole
```

---

## Integrazione con NETMON

### Webhook SIM → Policy engine

NETMON espone webhook che Headscale NETMON consuma in real-time:

| Evento NETMON | Azione Headscale |
|---|---|
| SIM disattivata | Revoca chiave WireGuard del dispositivo |
| Profilo degradato (SECURED → STANDARD) | Restringe ACL a risorse minime |
| SIM sospesa per morosità | Disconnessione immediata dal mesh |
| Nuovo dispositivo registrato | Pre-provisioning chiave WireGuard |
| Alert sicurezza (anomalia traffico) | Quarantena: accesso solo a NETMON portal |

### Vantaggio commerciale

Questa integrazione trasforma NETMON da **gestore di connettività** a
**orchestratore di accesso**. Il valore offerto al cliente diventa:

> "La tua SIM NETMON non è solo dati mobili — è l'identità verificata
>  del dispositivo. Se la SIM è attiva e il profilo corretto, il device
>  accede. Punto. Nessuna VPN da configurare, nessun firewall da aprire."

---

## Confronto con VPN tradizionale

| Dimensione | VPN aziendale | ZTNA Headscale NETMON |
|---|---|---|
| Accesso concesso a | Intera subnet | Singola risorsa/porta (ACL) |
| Cambio WiFi↔4G | Disconnessione e riconnessione | Trasparente (<1s) |
| Apertura porte firewall | Richiesta (UDP/1194 o TCP/443) | Zero porte in ingresso sul cliente |
| Autenticazione | All'avvio del tunnel | OIDC continuo + verifica SIM |
| Lateral movement | Possibile (flat network) | Impossibile (ACL per tag/gruppo) |
| IP camera / IoT | Complesso (no user auth) | Nativo (tag-based policy) |
| Overhead gestione | Alto (certificati, gateway) | Basso (Tailscale autoprovision) |
| Integrazione NETMON SIM | Nulla | Nativa (webhook real-time) |

---

## Piano di deployment

### Fase 1 — Pilota interno Technacy (2 settimane)

- [ ] Deploy Headscale NETMON su k3s laboratorio (namespace: `headscale-netmon`)
- [ ] Configurazione OIDC con Microsoft Entra ID Technacy
- [ ] Test con 3 iPhone staff Technacy (WiFi + SIM NETMON)
- [ ] Verifica trasparenza cambio mezzo (WiFi ↔ 4G)
- [ ] Documentazione procedure di enrollment dispositivi

### Fase 2 — Pilota con 1 cliente (4 settimane)

- [ ] Deploy Headscale Cliente on-premise (o VPS dedicato)
- [ ] Configurazione peering OIDC tra i due control plane
- [ ] Enrollment 5-10 dispositivi cliente
- [ ] Test exit node + accesso risorse LAN
- [ ] Integrazione webhook NETMON API (SIM status)
- [ ] Validazione failover WiFi → SIM senza interruzione

### Fase 3 — Produzione multi-tenant (go-to-market)

- [ ] Automazione provisioning Headscale Cliente (Terraform/Helm)
- [ ] Portal self-service per enrollment dispositivi
- [ ] Dashboard NETMON: stato mesh per tenant
- [ ] SLA: uptime 99.9%, failover <2s
- [ ] Pricing: da definire (per dispositivo/mese o flat per tenant)

---

## Requisiti di rete (firewall rules addizionali)

Per il funzionamento della soluzione Headscale, aggiungere al file
`01-iphone-base.json` le seguenti regole:

```json
{
  "id": "HS-001",
  "description": "Headscale NETMON — control plane HTTPS/gRPC",
  "protocol": "TCP",
  "destination_port": 443,
  "destination_fqdns": ["hs.netmon.it"],
  "action": "ALLOW"
},
{
  "id": "HS-002",
  "description": "WireGuard data plane — tunnel cifrato",
  "protocol": "UDP",
  "destination_port": 41641,
  "destination": "ANY",
  "action": "ALLOW",
  "notes": "Porta WireGuard default Tailscale. Fallback su UDP/3478 e TCP/443"
},
{
  "id": "HS-003",
  "description": "STUN — attraversamento NAT per peer discovery",
  "protocol": "UDP",
  "destination_port": 3478,
  "destination_fqdns": ["hs.netmon.it"],
  "action": "ALLOW"
},
{
  "id": "HS-004",
  "description": "DERP relay — fallback se WireGuard diretto non possibile",
  "protocol": "TCP",
  "destination_port": 443,
  "destination_fqdns": ["derp.netmon.it"],
  "action": "ALLOW",
  "notes": "Usato solo se NAT simmetrico impedisce connessione diretta"
}
```

---

## Riferimenti

- Headscale: https://headscale.net / https://github.com/juanfont/headscale
- WireGuard: https://www.wireguard.com
- Tailscale iOS: https://tailscale.com/kb/1020/install-ios
- Headscale OIDC: https://headscale.net/ref/oidc/
- Tailscale subnets: https://tailscale.com/kb/1019/subnets
- Tailscale exit nodes: https://tailscale.com/kb/1103/exit-nodes
- HuJSON ACL: https://tailscale.com/kb/1018/acls

Generato: 2026-03-31
Autore: Vittorio — Technacy srl
