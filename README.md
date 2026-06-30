# sqli-hunter

Scanner CLI en **Go** de vulnérabilités web courantes pour bug bounty.

## Vulnérabilités testées

| Type | Mode rapide | Mode complet |
|------|-------------|--------------|
| SQLi error-based | ✓ | ✓ |
| SQLi union-based | ✓ | ✓ |
| SQLi boolean-blind | ✓ | ✓ |
| SQLi time-blind | — | ✓ |
| XSS réfléchi | ✓ | ✓ |
| Open Redirect | ✓ | ✓ |
| LFI / Path Traversal | ✓ | ✓ |
| SSRF | ✓ | ✓ |

## Mode rapide (défaut)

- Payloads les plus efficaces uniquement (~30 tests/paramètre)
- Pas de time-based SQLi (trop lent)
- Arrêt anticipé par catégorie si vuln confirmée
- 8 threads, 100ms entre requêtes

## Installation

```bash
go build -o sqli-hunter ./cmd/sqli-hunter
```

## Usage

```bash
# Scan rapide complet (toutes les vulns communes)
./sqli-hunter -u "https://target.com/page?id=1"

# Cibler des vulns spécifiques
./sqli-hunter -u "https://target.com/search?q=test" -t sqli,xss

# Scan exhaustif avec time-based
./sqli-hunter -u "https://target.com/api?id=1" --full -t sqli

# Open redirect
./sqli-hunter -u "https://target.com/redirect?url=/" -t redirect

# LFI + SSRF
./sqli-hunter -u "https://target.com/file?path=index" -t lfi,ssrf -v
```

## Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-u, --url` | URL cible | — |
| `-t, --test` | `sqli,xss,redirect,lfi,ssrf` | toutes |
| `--full` | Scan complet (+ payloads, time-based) | off |
| `--waf` | Bypass WAF (SQLi) | off |
| `--threads` | Parallélisme | 8 |
| `--rate-limit` | Délai entre requêtes (ms) | 100 |
| `-v, --verbose` | Afficher chaque test | off |

## Avertissement

Utilisez cet outil **uniquement** sur des cibles autorisées (bug bounty, pentest contractuel, lab personnel).
