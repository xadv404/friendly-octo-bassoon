package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"encoding/json"
	"strconv"
	"strings"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
	"github.com/sqli-hunter/sqli-hunter/internal/runner"
)

const version = "1.14.0"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "discover":
			runDiscover(os.Args[2:])
			return
		case "-h", "--help":
			printUsage()
			return
		}
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	args := normalizeArgs(os.Args[1:])

	cfg, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	if cfg.showHelp {
		printUsage()
		return
	}
	if cfg.showVersion {
		fmt.Printf("sqli-hunter %s\n", version)
		return
	}

	if cfg.targetURL == "" && cfg.listFile == "" && cfg.discoverDomain == "" {
		fmt.Fprintln(os.Stderr, "erreur: -u, -l ou -D requis")
		os.Exit(1)
	}

	printer := output.New(cfg.noColor, cfg.verbose)
	printer.Header(version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		printer.Warning("interruption")
		cancel()
	}()

	if cfg.discoverDomain != "" {
		scopeFile, count, err := discoverURLs(ctx, cfg, printer)
		if err != nil {
			printer.Error(err.Error())
			os.Exit(1)
		}
		if count == 0 {
			printer.Error("aucune URL trouvée")
			os.Exit(1)
		}
		cfg.listFile = scopeFile
		applyMassDefaultsToConfig(&cfg, count)
	}

	if err := executeScan(ctx, cfg, printer); err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}
}

// normalizeArgs convertit un domaine positionnel en -D <domaine>.
// Ex: sqli-hunter css.ch → sqli-hunter -D css.ch
func normalizeArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	first := args[0]
	if strings.HasPrefix(first, "-") {
		return args
	}
	if strings.Contains(first, "://") {
		return args
	}
	// domaine nu (css.ch, *.css.ch)
	out := make([]string, 0, len(args)+1)
	out = append(out, "-D", first)
	return append(out, args[1:]...)
}

func applyMassDefaultsToConfig(cfg *config, urlCount int) {
	tmp := runner.Config{UrlConcurrency: cfg.urlConcurrency, ProgressEvery: cfg.progressEvery}
	applyMassDefaults(&tmp, urlCount, cfg.massMode)
	cfg.urlConcurrency = tmp.UrlConcurrency
	cfg.progressEvery = tmp.ProgressEvery
}

func applyMassDefaults(cfg *runner.Config, urlCount int, forceMass bool) {
	mass := forceMass || urlCount >= 500
	if !mass {
		return
	}
	if cfg.UrlConcurrency <= 4 {
		cfg.UrlConcurrency = 32
	}
	if cfg.ProgressEvery <= 0 {
		cfg.ProgressEvery = 100
	}
	if urlCount >= 10000 && cfg.UrlConcurrency < 64 {
		cfg.UrlConcurrency = 64
	}
}

type config struct {
	targetURL      string
	listFile       string
	discoverDomain string
	discoverOutput string
	discoverPaths  string
	discoverParams string
	discoverSubs   bool
	discoverNoFilter bool
	discoverLimit  int
	outputDir      string
	method         string
	params         map[string]string
	data           map[string]string
	headers        map[string]string
	cookies        map[string]string
	jsonBody       map[string]any
	categories     []models.VulnCategory
	techniques     []models.VulnType
	customPayloads []string
	fullScan       bool
	includeWAF     bool
	timeDelay      int
	timeThreshold  float64
	rateLimit      int
	timeout        int
	threads        int
	extractThreads int
	urlConcurrency int
	progressEvery  int
	massMode       bool
	extractMeta    bool
	verbose        bool
	noColor        bool
	showHelp       bool
	showVersion    bool
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		method:         "GET",
		timeDelay:      3,
		timeout:        15,
		threads:        8,
		extractThreads: 2,
		urlConcurrency: 4,
		rateLimit:      100,
		outputDir:      "results",
		discoverSubs:   true,
		params:         make(map[string]string),
		data:           make(map[string]string),
		headers:        make(map[string]string),
		cookies:        make(map[string]string),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			cfg.showHelp = true
		case arg == "--version":
			cfg.showVersion = true
		case arg == "-u" || arg == "--url":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-u nécessite une valeur")
			}
			cfg.targetURL = args[i]
		case arg == "-l" || arg == "--list":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-l nécessite un fichier")
			}
			cfg.listFile = args[i]
		case arg == "-D" || arg == "--domain":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-D nécessite un domaine")
			}
			cfg.discoverDomain = args[i]
		case arg == "--paths":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--paths nécessite une valeur")
			}
			cfg.discoverPaths = args[i]
		case arg == "--discover-params":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--discover-params nécessite une valeur")
			}
			cfg.discoverParams = args[i]
		case arg == "--discover-output":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--discover-output nécessite un fichier")
			}
			cfg.discoverOutput = args[i]
		case arg == "--subs":
			cfg.discoverSubs = true
		case arg == "--no-subs":
			cfg.discoverSubs = false
		case arg == "--no-filter":
			cfg.discoverNoFilter = true
		case arg == "--discover-limit":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--discover-limit nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--discover-limit doit être >= 1")
			}
			cfg.discoverLimit = v
		case arg == "-o" || arg == "--output":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-o nécessite un répertoire")
			}
			cfg.outputDir = args[i]
		case arg == "-m" || arg == "--method":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-m nécessite une valeur")
			}
			cfg.method = strings.ToUpper(args[i])
		case arg == "-p" || arg == "--param":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-p nécessite une valeur")
			}
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format param : nom=valeur")
			}
			cfg.params[parts[0]] = parts[1]
		case arg == "-d" || arg == "--data":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-d nécessite une valeur")
			}
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format data : nom=valeur")
			}
			cfg.data[parts[0]] = parts[1]
		case arg == "--json":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--json nécessite un corps JSON")
			}
			if err := json.Unmarshal([]byte(args[i]), &cfg.jsonBody); err != nil {
				return cfg, fmt.Errorf("JSON invalide : %w", err)
			}
		case arg == "-H" || arg == "--header":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-H nécessite une valeur")
			}
			parts := strings.SplitN(args[i], ":", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format header : Nom: Valeur")
			}
			cfg.headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		case arg == "-c" || arg == "--cookie":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-c nécessite une valeur")
			}
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format cookie : nom=valeur")
			}
			cfg.cookies[parts[0]] = parts[1]
		case arg == "-t" || arg == "--test":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-t nécessite une valeur")
			}
			for _, t := range strings.Split(args[i], ",") {
				cat, tech, err := payloads.ParseCategory(strings.TrimSpace(t))
				if err != nil {
					return cfg, err
				}
				cfg.categories = appendUniqueCategory(cfg.categories, cat)
				if tech != "" {
					cfg.techniques = append(cfg.techniques, tech)
				}
			}
		case arg == "--payload":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--payload nécessite une valeur")
			}
			cfg.customPayloads = append(cfg.customPayloads, args[i])
		case arg == "--full":
			cfg.fullScan = true
		case arg == "--waf":
			cfg.includeWAF = true
		case arg == "--time-delay":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--time-delay nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--time-delay doit être >= 1")
			}
			cfg.timeDelay = v
		case arg == "--time-threshold":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--time-threshold nécessite une valeur")
			}
			v, err := strconv.ParseFloat(args[i], 64)
			if err != nil {
				return cfg, fmt.Errorf("--time-threshold invalide")
			}
			cfg.timeThreshold = v
		case arg == "--rate-limit":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--rate-limit nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return cfg, fmt.Errorf("--rate-limit invalide")
			}
			cfg.rateLimit = v
		case arg == "--timeout":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--timeout nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return cfg, fmt.Errorf("--timeout invalide")
			}
			cfg.timeout = v
		case arg == "--threads":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--threads nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--threads doit être >= 1")
			}
			cfg.threads = v
		case arg == "--extract-threads":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--extract-threads nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--extract-threads doit être >= 1")
			}
			cfg.extractThreads = v
		case arg == "--url-threads":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--url-threads nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--url-threads doit être >= 1")
			}
			cfg.urlConcurrency = v
		case arg == "--progress-every":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--progress-every nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--progress-every doit être >= 1")
			}
			cfg.progressEvery = v
		case arg == "--mass":
			cfg.massMode = true
		case arg == "--extract-meta":
			cfg.extractMeta = true
		case arg == "-v" || arg == "--verbose":
			cfg.verbose = true
		case arg == "--no-color":
			cfg.noColor = true
		default:
			return cfg, fmt.Errorf("argument inconnu : %s", arg)
		}
	}

	return cfg, nil
}

func appendUniqueCategory(cats []models.VulnCategory, cat models.VulnCategory) []models.VulnCategory {
	for _, c := range cats {
		if c == cat {
			return cats
		}
	}
	return append(cats, cat)
}

func buildOptions(cfg config) models.ScanOptions {
	mode := models.ScanFast
	if cfg.fullScan {
		mode = models.ScanFull
	}
	categories := cfg.categories
	if len(categories) == 0 {
		categories = payloads.DefaultCategories(mode)
	}
	return models.ScanOptions{
		Categories:      categories,
		Techniques:      cfg.techniques,
		Mode:            mode,
		IncludeWAF:      cfg.includeWAF,
		CustomPayloads:  cfg.customPayloads,
		TimeDelaySec:    cfg.timeDelay,
		TimeThresholdMs: cfg.timeThreshold,
		RateLimitMs:     cfg.rateLimit,
		TimeoutSec:      cfg.timeout,
		Threads:         cfg.threads,
		ExtractThreads:  cfg.extractThreads,
		Verbose:         cfg.verbose,
		EarlyExit:       true,
		PIIOnly:         !cfg.extractMeta,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func printUsage() {
	fmt.Print(`sqli-hunter — détection SQLi/NoSQL · profil Suisse (.ch)

Usage:
  sqli-hunter <domaine.ch> [options]       Découverte Wayback + scan
  sqli-hunter -D <domaine.ch> [options]
  sqli-hunter -u <URL> [options]
  sqli-hunter -l <fichier> [options]
  sqli-hunter discover -d <domaine.ch> [options]

Découverte automatique (URLs .ch avec paramètres → scan vulnérabilités) :
  sqli-hunter ch              Tout le .ch (Wayback)
  sqli-hunter css.ch          Un seul domaine
  sqli-hunter ch --discover-limit 1000 --url-threads 64

Cible:
  -D, --domain <domaine>      ch = tout le .ch · css = css.ch · css.ch = un domaine
  -u, --url <URL>             URL unique avec paramètres
  -l, --list <fichier>        Fichier d'URLs (une par ligne, # commentaires)
  -o, --output <dir>          Répertoire de sortie [défaut: results]
                              → results/SITE.CH/SITE.CH.json
                              → results/SITE.CH/SITE.CH.sql
  -m, --method <METHOD>       GET ou POST [défaut: GET]
  -p, --param <nom=valeur>    Paramètre GET additionnel (mode -u)
  -d, --data <nom=valeur>     Paramètre POST (mode -u)
      --json <JSON>           Corps JSON (mode -u)

Découverte (avec -D) :
      --paths <a,b,c>         Filtre manuel path (optionnel)
      --discover-params <a,b> Filtre manuel paramètres (optionnel)
      --discover-output <f>   Fichier scope [défaut: scope_DOMAIN.ch.txt]
      --subs / --no-subs      Sous-domaines [défaut: oui]
      --no-filter             Toutes URLs .ch avec ?param= (ignore --paths)
      --discover-limit <n>    Max URLs à garder

Requête:
  -H, --header <Nom: Val>     Header HTTP (répétable)
  -c, --cookie <nom=val>      Cookie (répétable)

Injections:
  -t, --test <liste>          sqli,nosql,error,union,boolean,time
      --full                  Scan complet (+ time-based)
      --waf                   Payloads bypass WAF
      --payload <PAYLOAD>       Payload personnalisé

Performance:
      --threads <n>           Workers scan par URL [défaut: 8]
      --extract-threads <n>     Workers extraction [défaut: 2]
      --extract-meta            Extraire métadonnées DB (version, tables…) au lieu des PII
      --url-threads <n>         URLs en parallèle [défaut: 4, auto 32+ en mass]
      --progress-every <n>      Progression tous les N URLs [défaut: 100]
      --mass                    Force mode massif (streaming, dès 500 URLs auto)
      --rate-limit <ms>       Délai entre requêtes [défaut: 100]
      --timeout <sec>         Timeout HTTP [défaut: 15]

Affichage:
  -v, --verbose               Détails payloads et preuves
      --no-color              Sans couleurs
  -h, --help
      --version

Exemples:
  sqli-hunter ch --discover-limit 500 --url-threads 64
  sqli-hunter css.ch --url-threads 64
  sqli-hunter helsana --full
  sqli-hunter -u "https://target.ch/page?id=1"
  sqli-hunter -l urls.txt --url-threads 64
  sqli-hunter -l scope_50k.txt --mass --progress-every 500

`)
}
