package main

import "testing"

func TestNormalizeArgs_PositionalDomain(t *testing.T) {
	got := normalizeArgs([]string{"css.ch", "--preset", "insurance"})
	want := []string{"-D", "css.ch", "--preset", "insurance"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestNormalizeArgs_PreservesFlags(t *testing.T) {
	args := []string{"-u", "https://x.com?id=1"}
	if normalizeArgs(args)[0] != "-u" {
		t.Fatal("should not modify flag args")
	}
}

func TestNormalizeArgs_PreservesURL(t *testing.T) {
	args := []string{"https://css.ch/page?id=1"}
	if len(normalizeArgs(args)) != 1 || normalizeArgs(args)[0] != args[0] {
		t.Fatal("full URL should not become -D")
	}
}

func TestParseArgs_DiscoverDefaultNoFilter(t *testing.T) {
	cfg, err := parseArgs([]string{"-D", "css.ch"})
	if err != nil {
		t.Fatal(err)
	}
	if !discoverNoFilter(cfg) {
		t.Fatal("default discover should keep all URLs with params")
	}
}

func TestParseArgs_PresetDisablesNoFilter(t *testing.T) {
	cfg, err := parseArgs([]string{"-D", "css.ch", "--preset", "insurance"})
	if err != nil {
		t.Fatal(err)
	}
	if discoverNoFilter(cfg) {
		t.Fatal("preset should enable filtering")
	}
}

func TestParseArgs_NoFilterOverridesPreset(t *testing.T) {
	cfg, err := parseArgs([]string{"-D", "css.ch", "--preset", "insurance", "--no-filter"})
	if err != nil {
		t.Fatal(err)
	}
	if !discoverNoFilter(cfg) {
		t.Fatal("--no-filter should override preset")
	}
}

func TestParseArgs_DiscoverDomain(t *testing.T) {
	cfg, err := parseArgs([]string{"-D", "css.ch", "--preset", "insurance", "--url-threads", "32"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.discoverDomain != "css.ch" {
		t.Fatalf("domain: %q", cfg.discoverDomain)
	}
	if cfg.discoverPreset != "insurance" {
		t.Fatalf("preset: %q", cfg.discoverPreset)
	}
	if cfg.urlConcurrency != 32 {
		t.Fatalf("url threads: %d", cfg.urlConcurrency)
	}
}

func TestParseArgs_DiscoverNoFilter(t *testing.T) {
	cfg, err := parseArgs([]string{"-D", "target.com", "--no-filter", "--no-subs"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.discoverNoFilter {
		t.Fatal("no-filter expected")
	}
	if cfg.discoverSubs {
		t.Fatal("subs should be false")
	}
}

func TestApplyMassDefaultsToConfig(t *testing.T) {
	cfg := config{urlConcurrency: 4, progressEvery: 0}
	applyMassDefaultsToConfig(&cfg, 1000)
	if cfg.urlConcurrency != 32 {
		t.Fatalf("expected 32 url threads, got %d", cfg.urlConcurrency)
	}
	if cfg.progressEvery != 100 {
		t.Fatalf("expected progress 100, got %d", cfg.progressEvery)
	}
}
