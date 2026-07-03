package telegram

import (
	"errors"
	"testing"
)

func TestIsEditUnchanged(t *testing.T) {
	err := errors.New(`Bad Request: message is not modified: specified new message content and reply markup are exactly the same`)
	if !isEditUnchanged(err) {
		t.Fatal("expected unchanged")
	}
	if isEditUnchanged(errors.New("message to edit not found")) {
		t.Fatal("expected false for not found")
	}
}
