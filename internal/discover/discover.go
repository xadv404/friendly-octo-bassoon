package discover

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

// Source de collecte d'URLs.
type Source string

const (
	SourceBing    Source = "bing"
	SourceWayback Source = "wayback"
)

// ParseSource interprète --source (défaut: bing).
func ParseSource(s string) Source {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "wayback", "archive", "cdx":
		return SourceWayback
	default:
		return SourceBing
	}
}

// CDXFetcher récupère une page d'URLs depuis une source (Bing, Wayback, mock test).
type CDXFetcher interface {
	FetchPage(ctx context.Context, domain string, subs bool, page, limit int) ([]string, error)
}

// Options configure la découverte d'URLs.
type Options struct {
	Domain     string
	Output     string
	Subs       bool
	Paths      []string
	Params     []string
	NoFilter   bool
	Limit      int
	PageSize   int
	Source     Source
	ResultsDir string
	SkipDumped bool
	Fetcher    CDXFetcher
	OnProgress func(fetched, kept int, page int)
}

// Result résumé d'une découverte.
type Result struct {
	Fetched int
	Kept    int
	Skipped int
	Output  string
}

// Run collecte des URLs et écrit le fichier de scope.
func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.Domain == "" {
		return Result{}, fmt.Errorf("domaine requis")
	}
	if opts.Source == "" {
		opts.Source = SourceBing
	}
	opts.Domain = NormalizeSwissDomain(opts.Domain)

	if opts.Fetcher == nil {
		opts.Fetcher = defaultFetcher(opts.Source)
	}

	skipper, err := loadDumpSkipper(opts)
	if err != nil {
		return Result{}, err
	}

	if IsSwissWide(opts.Domain) {
		if opts.Source == SourceWayback {
			return runSwissWide(ctx, opts, skipper)
		}
		return runSingleDomain(ctx, opts, skipper)
	}
	if !strings.HasSuffix(opts.Domain, ".ch") {
		return Result{}, fmt.Errorf("domaine .ch requis (ex: css.ch) ou ch pour tout le .ch")
	}
	return runSingleDomain(ctx, opts, skipper)
}

func loadDumpSkipper(opts Options) (*results.DumpRegistry, error) {
	if !opts.SkipDumped {
		return nil, nil
	}
	dir := opts.ResultsDir
	if dir == "" {
		dir = "results"
	}
	return results.NewDumpRegistry(dir)
}

func runSwissWide(ctx context.Context, opts Options, skipper *results.DumpRegistry) (Result, error) {
	seeds := SwissSeedDomains()
	if skipper != nil {
		var filtered []string
		for _, d := range seeds {
			if !skipper.Contains(d) {
				filtered = append(filtered, d)
			}
		}
		seeds = filtered
	}
	if len(seeds) == 0 {
		return Result{}, fmt.Errorf("tous les domaines seeds sont déjà dumpés (ou liste vide)")
	}

	outPath := opts.Output
	if outPath == "" {
		outPath = "scope_ch.txt"
	}

	f, err := os.Create(outPath)
	if err != nil {
		return Result{}, fmt.Errorf("création %s : %w", outPath, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	perDomain := 50
	if opts.Limit > 0 {
		perDomain = opts.Limit / len(seeds)
		if perDomain < 5 {
			perDomain = 5
		}
	}

	seen := make(map[string]struct{})
	var fetched, kept, skipped int

	for i, domain := range seeds {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if opts.Limit > 0 && kept >= opts.Limit {
			break
		}

		subLimit := perDomain
		if opts.Limit > 0 {
			remaining := opts.Limit - kept
			if remaining < subLimit {
				subLimit = remaining
			}
		}

		subOpts := opts
		subOpts.Domain = domain
		subOpts.Limit = subLimit
		subOpts.Output = ""

		batchResult, err := collectDomain(ctx, subOpts, opts.Fetcher, seen, skipper, w)
		if err != nil {
			continue
		}
		fetched += batchResult.Fetched
		kept += batchResult.Kept
		skipped += batchResult.Skipped

		if opts.OnProgress != nil {
			opts.OnProgress(fetched, kept, i)
			fmt.Fprintf(os.Stderr, "\r  [%d/%d] %s — %d urls gardées", i+1, len(seeds), domain, kept)
		}
	}

	if kept == 0 {
		return Result{Fetched: fetched, Kept: 0, Skipped: skipped, Output: outPath},
			fmt.Errorf("aucune URL .ch scannable trouvée (mode ch, %d domaines testés)", len(seeds))
	}

	return Result{Fetched: fetched, Kept: kept, Skipped: skipped, Output: outPath}, nil
}

type collectResult struct {
	Fetched int
	Kept    int
	Skipped int
}

func collectDomain(ctx context.Context, opts Options, client CDXFetcher, seen map[string]struct{}, skipper *results.DumpRegistry, w *bufio.Writer) (collectResult, error) {
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 5000
	}

	var fetched, kept, skipped int
	for page := 0; ; page++ {
		if ctx.Err() != nil {
			return collectResult{}, ctx.Err()
		}

		batch, err := client.FetchPage(ctx, opts.Domain, opts.Subs, page, pageSize)
		if err != nil {
			return collectResult{fetched, kept, skipped}, err
		}
		if len(batch) == 0 {
			break
		}

		fetched += len(batch)
		for _, raw := range batch {
			norm := normalizeURL(raw)
			if shouldSkipDumped(norm, skipper) {
				skipped++
				continue
			}
			if !passesFilters(norm, opts) {
				continue
			}
			if _, ok := seen[norm]; ok {
				continue
			}
			seen[norm] = struct{}{}
			if _, err := w.WriteString(norm + "\n"); err != nil {
				return collectResult{}, err
			}
			kept++
			if opts.Limit > 0 && kept >= opts.Limit {
				return collectResult{fetched, kept, skipped}, nil
			}
		}

		if len(batch) < pageSize && opts.Source != SourceBing {
			break
		}
		if opts.Source == SourceBing && page > 200 {
			break
		}
	}
	return collectResult{fetched, kept, skipped}, nil
}

func runSingleDomain(ctx context.Context, opts Options, skipper *results.DumpRegistry) (Result, error) {
	if skipper != nil && !IsSwissWide(opts.Domain) && skipper.Contains(opts.Domain) {
		return Result{}, fmt.Errorf("domaine %s déjà dumpé (utilise --rescan pour forcer)", opts.Domain)
	}

	outPath := opts.Output
	if outPath == "" {
		outPath = "scope_" + sanitizeFilename(opts.Domain) + ".txt"
	}

	f, err := os.Create(outPath)
	if err != nil {
		return Result{}, fmt.Errorf("création %s : %w", outPath, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	seen := make(map[string]struct{})
	collectWithProgress := func(fetched, kept, page int) {
		if opts.OnProgress != nil {
			opts.OnProgress(fetched, kept, page)
		}
	}

	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 5000
	}

	var fetched, kept, skipped int
	for page := 0; ; page++ {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}

		batch, err := opts.Fetcher.FetchPage(ctx, opts.Domain, opts.Subs, page, pageSize)
		if err != nil {
			return Result{}, err
		}
		if len(batch) == 0 {
			break
		}

		fetched += len(batch)
		for _, raw := range batch {
			norm := normalizeURL(raw)
			if shouldSkipDumped(norm, skipper) {
				skipped++
				continue
			}
			if !passesFilters(norm, opts) {
				continue
			}
			if _, ok := seen[norm]; ok {
				continue
			}
			seen[norm] = struct{}{}
			if _, err := w.WriteString(norm + "\n"); err != nil {
				return Result{}, err
			}
			kept++
			if opts.Limit > 0 && kept >= opts.Limit {
				collectWithProgress(fetched, kept, page)
				return Result{Fetched: fetched, Kept: kept, Skipped: skipped, Output: outPath}, nil
			}
		}

		collectWithProgress(fetched, kept, page)

		if len(batch) < pageSize && opts.Source != SourceBing {
			break
		}
		if opts.Source == SourceBing && page > 200 {
			break
		}
	}

	if kept == 0 {
		return Result{Fetched: fetched, Kept: 0, Skipped: skipped, Output: outPath},
			fmt.Errorf("aucune URL .ch scannable trouvée pour %s", opts.Domain)
	}

	return Result{Fetched: fetched, Kept: kept, Skipped: skipped, Output: outPath}, nil
}

func shouldSkipDumped(raw string, skipper *results.DumpRegistry) bool {
	if skipper == nil {
		return false
	}
	domain, err := results.DomainFromURL(raw)
	if err != nil {
		return false
	}
	return skipper.Contains(domain)
}

func passesFilters(raw string, opts Options) bool {
	if !isScannable(raw) {
		return false
	}
	if opts.NoFilter {
		return true
	}
	pathMatch := matchKeywords(raw, opts.Paths)
	paramMatch := matchParamNames(raw, opts.Params)

	switch {
	case len(opts.Paths) == 0 && len(opts.Params) == 0:
		return true
	case len(opts.Paths) > 0 && len(opts.Params) > 0:
		return pathMatch && paramMatch
	case len(opts.Paths) > 0:
		return pathMatch
	default:
		return paramMatch
	}
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

// ParseList découpe une liste séparée par des virgules.
func ParseList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
