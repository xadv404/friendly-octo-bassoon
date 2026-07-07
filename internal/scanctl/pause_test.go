package scanctl

import "testing"

func TestParsePIDFromLine(t *testing.T) {
	pid, err := parsePIDFromLine("4242 ./sqli-hunter hunt")
	if err != nil || pid != 4242 {
		t.Fatalf("got %d %v", pid, err)
	}
	if _, err := parsePIDFromLine(""); err == nil {
		t.Fatal("expected error")
	}
}
