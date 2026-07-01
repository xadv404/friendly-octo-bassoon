package main

import "testing"

func TestNormalizeArgs_PositionalDomain(t *testing.T) {
	got := normalizeArgs([]string{"css.ch", "--url-threads", "64"})
	want := []string{"-D", "css.ch", "--url-threads", "64"}
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
	args := []string{"-u", "https://x.ch?id=1"}
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
		t.Fatal("default discover should keep all .ch URLs with params")
	}
}

func TestParseArgs_PathFilterDisablesNoFilter(t *testing.T) {
	cfg, err := parseArgs([]string{"-D", "css.ch", "--paths", "api"})
	if err != nil {
		t.Fatal(err)
	}
	if discoverNoFilter(cfg) {
		t.Fatal("paths filter should enable filtering")
	}
}

func TestParseArgs_DiscoverDomain(t *testing.T) {
	cfg, err := parseArgs([]string{"-D", "css", "--url-threads", "32"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.discoverDomain != "css" {
		t.Fatalf("domain: %q", cfg.discoverDomain)
	}
	if cfg.urlConcurrency != 32 {
		t.Fatalf("url threads: %d", cfg.urlConcurrency)
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
