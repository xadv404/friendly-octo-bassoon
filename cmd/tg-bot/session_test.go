package main

import "testing"

func TestPendingQty(t *testing.T) {
	p := newPendingQty()
	p.Set(42, "gmail.com")
	got, ok := p.Get(42)
	if !ok || got != "gmail.com" {
		t.Fatalf("got %q %v", got, ok)
	}
	p.Clear(42)
	_, ok = p.Get(42)
	if ok {
		t.Fatal("expected cleared")
	}
}
