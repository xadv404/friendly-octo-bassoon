package discover

import (
	"testing"
)

func TestParseProxyURL_BPFormat(t *testing.T) {
	raw := "http://bpuser-dCNEeLEO:SKioubriwkHIQthVgJGa:residential.bpproxy.at:1000"
	u, err := parseProxyURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != "residential.bpproxy.at" || u.Port() != "1000" {
		t.Fatalf("host: %s", u.Host)
	}
	user, pass := u.User.Username(), ""
	if p, ok := u.User.Password(); ok {
		pass = p
	}
	if user != "bpuser-dCNEeLEO" || pass != "SKioubriwkHIQthVgJGa" {
		t.Fatalf("auth %s:%s", user, pass)
	}
}

func TestParseProxyURL_Standard(t *testing.T) {
	u, err := parseProxyURL("http://user:pass@proxy.example.com:8080")
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "proxy.example.com:8080" {
		t.Fatalf("got %s", u.Host)
	}
}

func TestReloadProxyPool(t *testing.T) {
	t.Setenv("DISCOVER_PROXY", "http://u:p:host.test:1234")
	ReloadProxyPool()
	if !getProxyPool().hasProxies() {
		t.Fatal("expected proxy loaded")
	}
	u := getProxyPool().first()
	if u.Hostname() != "host.test" {
		t.Fatalf("got %v", u)
	}
}
