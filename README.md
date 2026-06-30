# sqli-hunter

Outil CLI en **Go** de détection SQL injection pour bug bounty.

## Fonctionnalités

- **Error-based** — détection d'erreurs SQL (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **Boolean-based blind** — comparaison réponses vrai/faux
- **Time-based blind** — détection par délai (SLEEP, pg_sleep, WAITFOR DELAY…)
- **Union-based** — tests UNION SELECT
- **WAF bypass** — payloads d'évasion courants
- **Payloads personnalisés**
- **GET / POST / JSON**
- **Headers & cookies** configurables
- **Multi-thread** avec rate limiting
- **Sortie CLI colorée** en temps réel

## Installation

```bash
go build -o sqli-hunter ./cmd/sqli-hunter
```

## Usage

```bash
# Scan GET basique (params extraits de l'URL)
./sqli-hunter -u "https://target.com/page?id=1"

# POST avec techniques spécifiques
./sqli-hunter -u "https://target.com/login" -m POST \
  -d "user=admin" -d "pass=test" \
  -t error,boolean

# Time-based avec WAF bypass
./sqli-hunter -u "https://target.com/search?q=test" \
  -p "q=test" -t time --time-delay 3 --waf -v

# API JSON avec authentification
./sqli-hunter -u "https://target.com/api/users" \
  --json '{"id":1}' \
  -H "Authorization: Bearer TOKEN" \
  -t error,union

# Payload personnalisé
./sqli-hunter -u "https://target.com/item?id=1" \
  --payload "1' AND 1=1--" --payload "1' AND 1=2--"
```

## Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-u, --url` | URL cible | — |
| `-m, --method` | Méthode HTTP | GET |
| `-p, --param` | Paramètre GET (`nom=valeur`) | — |
| `-d, --data` | Paramètre POST (`nom=valeur`) | — |
| `--json` | Corps JSON | — |
| `-H, --header` | Header HTTP | — |
| `-c, --cookie` | Cookie | — |
| `-t, --technique` | `error`, `boolean`, `time`, `union` | toutes |
| `--waf` | Payloads bypass WAF | off |
| `--payload` | Payload custom | — |
| `--time-delay` | Délai time-based (sec) | 5 |
| `--rate-limit` | Délai entre requêtes (ms) | 200 |
| `--timeout` | Timeout HTTP (sec) | 15 |
| `--threads` | Parallélisme | 5 |
| `-v, --verbose` | Afficher chaque test | off |

## Avertissement

Utilisez cet outil **uniquement** sur des cibles pour lesquelles vous avez une autorisation explicite (programme bug bounty, pentest contractuel, lab personnel).
