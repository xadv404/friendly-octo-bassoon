package discover

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
)

// CDXFetcher récupère une page d'URLs depuis une source (Wayback, mock test).
type CDXFetcher interface {
	FetchPage(ctx context.Context, domain string, subs bool, page, limit int) ([]string, error)
}

// Options configure la découverte d'URLs.
type Options struct {
	Domain     string
	Output     string
	Subs       bool
	Paths      []string // filtre manuel optionnel
	Params     []string // filtre manuel optionnel
	NoFilter   bool     // ignore Paths/Params — toutes URLs .ch avec ?key=val
	Limit      int      // max URLs écrites (0 = illimité)
	PageSize   int
	Fetcher    CDXFetcher
	OnProgress func(fetched, kept int, page int)
}

// Result résumé d'une découverte.
type Result struct {
	Fetched int
	Kept    int
	Output  string
}

// Run collecte des URLs via Wayback CDX et écrit le fichier de scope.
func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.Domain == "" {
		return Result{}, fmt.Errorf("domaine requis")
	}
	opts.Domain = NormalizeSwissDomain(opts.Domain)
	if !strings.HasSuffix(opts.Domain, ".ch") {
		return Result{}, fmt.Errorf("domaine .ch requis (ex: css.ch)")
	}

	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 5000
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
	client := opts.Fetcher
	if client == nil {
		client = newWaybackClient()
	}

	var fetched, kept int
	for page := 0; ; page++ {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}

		batch, err := client.FetchPage(ctx, opts.Domain, opts.Subs, page, pageSize)
		if err != nil {
			return Result{}, err
		}
		if len(batch) == 0 {
			break
		}

		fetched += len(batch)
		for _, raw := range batch {
			norm := normalizeURL(raw)
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
				if opts.OnProgress != nil {
					opts.OnProgress(fetched, kept, page)
				}
				return Result{Fetched: fetched, Kept: kept, Output: outPath}, nil
			}
		}

		if opts.OnProgress != nil {
			opts.OnProgress(fetched, kept, page)
		}

		if len(batch) < pageSize {
			break
		}
	}

	if kept == 0 {
		return Result{Fetched: fetched, Kept: 0, Output: outPath},
			fmt.Errorf("aucune URL .ch scannable trouvée pour %s", opts.Domain)
	}

	return Result{Fetched: fetched, Kept: kept, Output: outPath}, nil
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
