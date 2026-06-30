# sqli-hunter

Scanner CLI en **Go** dédié aux **injections donnant accès à la base de données**.

## Cible : accès DB uniquement

| Type | Objectif |
|------|----------|
| **SQLi error-based** | Erreurs SQL → requêtes injectables |
| **SQLi union-based** | Extraction `version()`, `database()`, `information_schema` |
| **SQLi boolean-blind** | Manipulation de requêtes SELECT |
| **SQLi time-blind** | Exécution de requêtes temporisées (`--full`) |
| **NoSQL injection** | Bypass auth MongoDB, accès collections |

Payloads orientés **extraction de métadonnées DB** : version, schémas, tables, utilisateurs.

## Listes d'URLs (bulk)

```bash
# Fichier urls.txt — une URL par ligne, paramètres dans la query
# https://target.com/page?id=1
# https://api.example.com/users?uid=42

./sqli-hunter -l urls.txt --url-threads 8 -o results.json
```

| Option | Description | Défaut |
|--------|-------------|--------|
| `-l, --list` | Fichier d'URLs | — |
| `-o, --output` | Répertoire de sortie | `results` |
| `--url-threads` | URLs scannées en parallèle | 4 |
| `--threads` | Workers scan par URL | 8 |
| `--extract-threads` | Workers extraction | 2 |

En mode liste : progression `[42/1240]`, vulns affichées immédiatement, résumé final compact.

## Extraction de données

Dès qu'une vulnérabilité est détectée, l'outil lance automatiquement l'extraction sur des **workers dédiés** (séparés des threads de scan). Le scan continue en parallèle sans bloquer.

| Option | Description | Défaut |
|--------|-------------|--------|
| `--threads` | Goroutines de scan | 8 |
| `--extract-threads` | Workers d'extraction | 2 |

### Données extraites

- Version DB (`@@version`, `version()`)
- Nom de la base (`database()`, `current_database()`)
- Utilisateur DB (`user()`, `system_user`)
- Tables (`information_schema`, `sqlite_master`)
- Dump NoSQL (collections MongoDB)

## Sortie des résultats

Par défaut, les rapports sont écrits dans `results/` :

```
results/
  target.com/
    target.com.json    ← rapport complet (vulns + extractions)
    target.com.sql     ← dump commenté des données extraites
  api.shop.io/
    api.shop.io.json
    api.shop.io.sql
```

Les URLs d'un même domaine sont regroupées dans un seul rapport.

```bash
./sqli-hunter -l urls.txt                    # → results/
./sqli-hunter -u "https://x.com/p?id=1" -o results
```

## Installation

```bash
go build -o sqli-hunter ./cmd/sqli-hunter
```

## Usage

```bash
# Scan rapide SQLi + NoSQL
./sqli-hunter -u "https://target.com/page?id=1"

# SQLi uniquement
./sqli-hunter -u "https://target.com/product?id=1" -t sqli

# Union + extraction DB
./sqli-hunter -u "https://target.com/item?id=1" -t union -v

# Scan complet (time-based inclus)
./sqli-hunter -u "https://target.com/api?id=1" --full
```

## Benchmark local — 24 scénarios réalistes

```bash
go run ./cmd/benchmark
go test ./internal/benchmark/... -v
```

### Contextes applicatifs testés

| Contexte | Scénarios | Exemple réel |
|----------|-----------|--------------|
| E-commerce | 3 | testphp.vulnweb.com, fiche produit, recherche |
| Authentification | 3 | DVWA login, Juice Shop MongoDB |
| API REST | 3 | Spring Boot, Node.js JSON, ASP.NET pagination |
| Panel admin | 3 | EXTRACTVALUE, MSSQL search, logs blind |
| Santé | 2 | Oracle patient, SQLite labo |
| Banque | 2 | PostgreSQL relevé, virement blind |
| Blog/CMS | 2 | WordPress slug, UNION database() |
| Legacy PHP | 2 | artists.php, avis POST |
| SaaS B2B | 2 | CRM MSSQL, tenant NoSQL $regex |
| Réservation | 2 | Booking ref, moteur vols PG |
| **Négatifs** | 2 | Page statique, requêtes préparées |

### DBMS couverts

MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB

### Tests unitaires

```bash
go test ./... -v   # 50+ cas : erreurs SQL par DBMS, boolean blind, UNION, NoSQL, faux positifs
```


```bash
./sqli-hunter -u "http://testphp.vulnweb.com/artists.php?artist=1" -t sqli -v
./sqli-hunter -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -t sqli,union
```

## Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-t, --test` | `sqli`, `nosql`, `error`, `union`, `boolean`, `time` | sqli + nosql |
| `--full` | Scan complet + time-based | off |
| `--waf` | Bypass WAF SQLi | off |

## Avertissement

Utilisez uniquement sur des cibles autorisées (bug bounty, pentest, lab).
