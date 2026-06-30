# sqli-hunter

Scanner CLI en **Go** de vulnérabilités web courantes pour bug bounty.

## Alignement OWASP Top 10:2025 / bug bounty 2026

Sources : OWASP Top 10:2025, Synack State of Vulnerabilities 2026, Penetrify Q1 2026.

| Rang OWASP 2025 | Part estimée | Couvert par sqli-hunter |
|-----------------|--------------|-------------------------|
| A01 Broken Access Control | ~34% | **IDOR**, **LFI** |
| A05 Injection | ~22% | **SQLi**, **XSS**, **SSTI** |
| A02 Security Misconfiguration | ~18% | **SSRF** (partiel) |
| Open Redirect | fréquent en bounty | **Open Redirect** |

> Les catégories non couvertes (auth failures, supply chain, crypto, misconfig générale) nécessitent des tests manuels ou des outils complémentaires.

## Vulnérabilités testées

| Type | Mode rapide | Mode complet |
|------|-------------|--------------|
| SQLi (error, union, boolean) | ✓ | ✓ |
| SQLi time-blind | — | ✓ |
| XSS réfléchi | ✓ | ✓ |
| SSTI | ✓ | ✓ |
| Open Redirect | ✓ | ✓ |
| LFI / Path Traversal | ✓ | ✓ |
| SSRF | ✓ | ✓ |
| IDOR | ✓ | ✓ |

## Entraînement / benchmark

Les sites publics (vulnweb, testfire) bloquent souvent les IP cloud. Un **serveur vulnérable local** est inclus pour valider la détection :

```bash
# Lancer le benchmark (7 vulns simulées)
go run ./cmd/benchmark

# Ou via les tests
go test ./internal/benchmark/... -v
```

Le benchmark teste automatiquement :
- SQLi error-based sur `/sqli?id=1`
- XSS sur `/xss?q=test`
- Open Redirect sur `/redirect?url=/`
- LFI sur `/file?path=index`
- SSRF sur `/fetch?url=...`
- SSTI sur `/template?name=world`
- IDOR sur `/user?id=1`

## Installation

```bash
go build -o sqli-hunter ./cmd/sqli-hunter
```

## Usage

```bash
# Scan rapide — toutes les vulns communes
./sqli-hunter -u "https://target.com/page?id=1"

# Cibler sqli + xss + ssti
./sqli-hunter -u "https://target.com/search?q=test" -t sqli,xss,ssti

# Scan exhaustif
./sqli-hunter -u "https://target.com/api?id=1" --full
```

## Sites de test publics (à lancer depuis ta machine)

| Site | Vulns connues |
|------|---------------|
| http://testphp.vulnweb.com | SQLi, XSS, LFI |
| http://testasp.vulnweb.com | SQLi (ASP) |
| https://juice-shop.herokuapp.com | OWASP Juice Shop (complet) |
| DVWA / WebGoat | Local (Docker) |

```bash
# Exemple depuis ton réseau local
./sqli-hunter -u "http://testphp.vulnweb.com/artists.php?artist=1" -t sqli -v
./sqli-hunter -u "http://testphp.vulnweb.com/search.php?test=query" -t xss,sqli
```

## Avertissement

Utilisez cet outil **uniquement** sur des cibles autorisées (bug bounty, pentest contractuel, lab personnel).
