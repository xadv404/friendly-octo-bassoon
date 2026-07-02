package targets

import (
	"testing"
)

func TestFromURL_QueryParams(t *testing.T) {
	tgt, err := FromURL("http://example.com/page?id=1&cat=2", Defaults{})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Params["id"] != "1" || tgt.Params["cat"] != "2" {
		t.Fatalf("params: %v", tgt.Params)
	}
	if tgt.Method != "GET" {
		t.Fatalf("method: %s", tgt.Method)
	}
}

func TestFromURL_NoParams(t *testing.T) {
	_, err := FromURL("http://example.com/static", Defaults{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFromURL_GlobalHeaders(t *testing.T) {
	tgt, err := FromURL("http://example.com/api?user=1", Defaults{
		Headers: map[string]string{"Authorization": "Bearer x"},
		Cookies: map[string]string{"session": "abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Headers["Authorization"] != "Bearer x" {
		t.Fatal("header missing")
	}
}
