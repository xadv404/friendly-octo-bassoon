package discover

import (
	"bufio"
	"context"

	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

// DorkDirectFetcher exécute une requête dork explicite (fresh-pass quotidien).
type DorkDirectFetcher interface {
	FetchDork(ctx context.Context, dork string, start int) ([]string, error)
}

type freshCollectState struct {
	fetched int
	kept    int
	skipped int
}

func runFreshPass(
	ctx context.Context,
	opts Options,
	fetcher CDXFetcher,
	skipper *results.DumpRegistry,
	scanned *results.ScannedRegistry,
	seen map[string]struct{},
	w *bufio.Writer,
) (freshCollectState, error) {
	direct, ok := fetcher.(DorkDirectFetcher)
	if !ok {
		return freshCollectState{}, nil
	}

	dorks := BuildFreshDorks(opts.Domain, opts.Subs)
	if len(dorks) == 0 {
		return freshCollectState{}, nil
	}

	var st freshCollectState
	for i, dork := range dorks {
		if ctx.Err() != nil {
			return st, ctx.Err()
		}
		if opts.Limit > 0 && st.kept >= opts.Limit {
			return st, nil
		}

		batch, err := direct.FetchDork(ctx, dork, 0)
		if err != nil {
			if opts.OnFreshProgress != nil {
				opts.OnFreshProgress(i+1, len(dorks), st.kept, st.fetched, st.skipped)
			}
			continue
		}
		if len(batch) == 0 {
			continue
		}

		st.fetched += len(batch)
		for _, raw := range batch {
			if opts.Limit > 0 && st.kept >= opts.Limit {
				return st, nil
			}
			norm := normalizeURL(raw)
			if shouldSkipDumped(norm, skipper) {
				st.skipped++
				continue
			}
			if shouldSkipScanned(norm, scanned) {
				st.skipped++
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
				return st, err
			}
			st.kept++
			if opts.OnURLKept != nil {
				opts.OnURLKept(norm)
			}
		}
		if opts.OnFreshProgress != nil {
			opts.OnFreshProgress(i+1, len(dorks), st.kept, st.fetched, st.skipped)
		}
	}
	return st, nil
}
