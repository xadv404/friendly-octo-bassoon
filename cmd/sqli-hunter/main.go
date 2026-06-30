package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
	"github.com/sqli-hunter/sqli-hunter/internal/scanner"
)

const version = "1.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
		os.Exit(1)
	}

	if cfg.showHelp {
		printUsage()
		return
	}
	if cfg.showVersion {
		fmt.Printf("sqli-hunter v%s\n", version)
		return
	}

	printer := output.NewPrinter(cfg.noColor)
	printer.Banner()

	if cfg.targetURL == "" {
		printer.Error("URL requise (-u)")
		os.Exit(1)
	}

	target, err := buildTarget(cfg)
	if err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}

	opts := buildOptions(cfg)
	printer.Info(fmt.Sprintf("Cible : %s", cfg.targetURL))
	printer.Info(fmt.Sprintf("Méthode : %s", target.Method))
	printer.PrintScanConfig(opts.Mode, opts.Categories, opts.IncludeWAF)
	printer.Info(fmt.Sprintf("Threads : %d | Timeout : %ds | Rate limit : %dms", opts.Threads, opts.TimeoutSec, opts.RateLimitMs))
	fmt.Println()

	httpClient := client.New(opts.TimeoutSec, target.Headers, target.Cookies)
	sc := scanner.New(httpClient, opts,
		func(f models.Finding) { printer.Finding(f) },
		func(msg string) { printer.Verbose(msg) },
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		printer.Warning("Interruption — arrêt en cours...")
		cancel()
	}()

	start := time.Now()
	result := sc.Scan(ctx, target)
	elapsed := time.Since(start)

	printer.Summary(result)
	printer.Info(fmt.Sprintf("Durée : %s", elapsed.Round(time.Millisecond)))
}

type config struct {
	targetURL      string
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
	verbose        bool
	noColor        bool
	showHelp       bool
	showVersion    bool
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		method:    "GET",
		timeDelay: 3,
		timeout:   15,
		threads:   8,
		rateLimit: 100,
		params:    make(map[string]string),
		data:      make(map[string]string),
		headers:   make(map[string]string),
		cookies:   make(map[string]string),
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

func buildTarget(cfg config) (models.ScanTarget, error) {
	u, err := url.Parse(cfg.targetURL)
	if err != nil {
		return models.ScanTarget{}, fmt.Errorf("URL invalide : %w", err)
	}

	if len(cfg.params) == 0 && u.RawQuery != "" {
		for k, vals := range u.Query() {
			if len(vals) > 0 {
				cfg.params[k] = vals[0]
			}
		}
	}

	if len(cfg.params) == 0 && len(cfg.data) == 0 && cfg.jsonBody == nil {
		return models.ScanTarget{}, fmt.Errorf("aucun paramètre — utilisez -p, -d ou --json")
	}

	method := cfg.method
	if len(cfg.data) > 0 || cfg.jsonBody != nil {
		if method == "GET" {
			method = "POST"
		}
	}

	return models.ScanTarget{
		URL: cfg.targetURL, Method: method,
		Params: cfg.params, Data: cfg.data,
		Headers: cfg.headers, Cookies: cfg.cookies,
		JSONBody: cfg.jsonBody,
	}, nil
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
		Verbose:         cfg.verbose,
		EarlyExit:       true,
	}
}

func printUsage() {
	fmt.Print(`sqli-hunter — Scanner rapide de vulnérabilités web pour bug bounty

Usage:
  sqli-hunter -u <URL> [options]

Cible:
  -u, --url <URL>           URL cible (requise)
  -m, --method <METHOD>     Méthode HTTP (GET, POST) [défaut: GET]
  -p, --param <nom=valeur>  Paramètre GET (répétable)
  -d, --data <nom=valeur>   Paramètre POST form (répétable)
      --json <JSON>         Corps JSON (ex: '{"id":1}')

Requête:
  -H, --header <Nom: Val>   Header HTTP (répétable)
  -c, --cookie <nom=val>    Cookie (répétable)

Vulnérabilités (mode rapide par défaut):
  -t, --test <liste>        sqli,xss,redirect,lfi,ssrf [défaut: toutes]
                            SQLi fin : error,boolean,time,union
      --full                Scan complet (plus de payloads + time-based)
      --waf                 Payloads bypass WAF (SQLi)
      --payload <PAYLOAD>     Payload SQLi personnalisé (répétable)

Timing:
      --time-delay <sec>    Délai time-based [défaut: 3]
      --time-threshold <ms> Seuil détection time-based
      --rate-limit <ms>     Délai entre requêtes [défaut: 100]
      --timeout <sec>       Timeout HTTP [défaut: 15]
      --threads <n>         Goroutines parallèles [défaut: 8]

Affichage:
  -v, --verbose             Afficher chaque test
      --no-color            Désactiver les couleurs
  -h, --help                Aide
      --version             Version

Exemples:
  sqli-hunter -u "https://target.com/page?id=1"
  sqli-hunter -u "https://target.com/search?q=test" -t sqli,xss
  sqli-hunter -u "https://target.com/redirect?url=/" -t redirect
  sqli-hunter -u "https://target.com/file?path=index" -t lfi,ssrf --full -v

Mode rapide (défaut):
  - SQLi error + union + boolean (pas de time-based)
  - XSS, Open Redirect, LFI, SSRF
  - Payloads les plus efficaces uniquement
  - Arrêt anticipé par catégorie si vuln confirmée

⚠️  Utilisez uniquement sur des cibles autorisées (bug bounty, pentest contractuel).
`)
}
