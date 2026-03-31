# firewall-iphone-rules

Regole minime di firewall per consentire a un iPhone connesso su rete Wi-Fi aziendale
di funzionare come telefono (Wi-Fi Calling) e autenticarsi con i principali IdP.

## Struttura

```
firewall-iphone-rules/
├── 01-iphone-base.json        # Regole base: Wi-Fi Calling + Microsoft 365
├── 02-google-auth.json        # Addon: Google OAuth2/OIDC + Authenticator
├── 03-okta-auth0.json         # Addon: Okta Identity Engine + Auth0
├── apply-iphone-firewall.sh   # Script bash per applicare le regole con iptables
└── README.md                  # Questo file
```

## Policy di default

Tutti i file presuppongono un firewall con **default DROP** in output.
Le regole aprono esclusivamente i flussi documentati.

## Prerequisiti script bash

```bash
# Debian/Ubuntu
sudo apt install iptables ipset iptables-persistent

# RHEL/CentOS/Rocky
sudo yum install iptables ipset iptables-services
```

## Utilizzo

### Dry run (nessuna modifica, solo preview)
```bash
sudo bash apply-iphone-firewall.sh --dry-run
```

### Applicazione completa
```bash
sudo bash apply-iphone-firewall.sh
```

### Applicazione senza persistenza
```bash
sudo bash apply-iphone-firewall.sh --no-persist
```

### Personalizzazione (obbligatoria per Auth0)
Editare le variabili in cima allo script:
```bash
AUTH0_TENANT="mycompany"      # nome del tenant Auth0
AUTH0_REGION="eu"             # us | eu | au
CUSTOM_DOMAIN="login.azienda.it"  # custom domain Auth0 (opzionale)
IFACE="eth0"                  # interfaccia di rete (vuoto = tutte)
```

Per Okta, aggiungere il FQDN concreto del tenant nella sezione OKTA-001:
```bash
allow_fqdn_https "mycompany.okta.com"
```

## Note architetturali

| Provider | Porta | Protocollo | Note |
|---|---|---|---|
| DNS | 53 | UDP+TCP | Prerequisito per tutto |
| NTP | 123 | UDP | Critico per TLS/autenticazione |
| Apple APNs | 5223, 443, 2197 | TCP | Verso 17.0.0.0/8 (Apple) |
| Wi-Fi Calling | 500, 4500 | UDP | IKEv2 + IPsec NAT-T |
| Microsoft 365 | 443 | TCP | FQDN login.microsoftonline.com etc. |
| Google Auth | 443, 80 | TCP | FQDN + PKI Google (pki.goog) |
| Okta | 443, 80 | TCP | *.okta.com, *.oktacdn.com |
| Auth0 | 443, 80 | TCP | TENANT.auth0.com, cdn.auth0.com |

**Importante:** iptables non supporta FQDN wildcard nativamente.
Lo script risolve i FQDN al momento dell'applicazione con `getent`.
Per ambienti con IP dinamici frequenti considerare:
- `iptables-dns` (risoluzione periodica)
- Un DNS-based firewall (pfSense + pfBlockerNG, Fortinet, Palo Alto)
- Un proxy HTTPS forward con whitelist FQDN

**Non applicare SSL inspection** su traffico verso:
- `17.0.0.0/8` (Apple)
- `*.googleapis.com`, `accounts.google.com`
- `*.okta.com`, `*.oktacdn.com`
- `*.auth0.com`

## Fonti ufficiali

- Apple APNs: https://support.apple.com/en-us/102266
- Apple enterprise networks: https://support.apple.com/en-us/101555
- Microsoft 365 endpoints: https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges
- Google Workspace allowlist: https://support.google.com/a/answer/9012184
- Okta IP allowlist: https://help.okta.com/oie/en-us/content/topics/security/ip-address-allow-listing.htm
- Auth0 IP allowlist: https://auth0.com/docs/secure/security-guidance/data-security/allowlist

Generato: 2026-03-31
