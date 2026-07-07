package botapp

import "testing"

func TestPendingQty(t *testing.T) {
	p := newPendingQty()
	p.Set(1, "gmail.com")
	prov, ok := p.Get(1)
	if !ok || prov != "gmail.com" {
		t.Fatalf("got %q %v", prov, ok)
	}
	p.Clear(1)
	if _, ok := p.Get(1); ok {
		t.Fatal("expected cleared")
	}
}
