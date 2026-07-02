package urllist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	var content string
	for i := 0; i < 1000; i++ {
		content += "https://example.com/page?id=" + strconvItoa(i) + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := Count(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1000 {
		t.Fatalf("count %d want 1000", n)
	}
}

func TestStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(path, []byte("https://a.com/x?id=1\nhttps://b.com/y?id=2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 10)
	go func() {
		if err := Stream(path, ch); err != nil {
			t.Error(err)
		}
	}()
	var got []string
	for u := range ch {
		got = append(got, u)
	}
	if len(got) != 2 {
		t.Fatalf("got %d urls", len(got))
	}
}

func strconvItoa(i int) string {
	return fmtInt(i)
}

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
