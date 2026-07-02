package i18n

import "testing"

func TestForLocale_FR(t *testing.T) {
	b := ForLocale(FR)
	if b.Bot.BotName != "MAIL LIST" {
		t.Fatalf("bot name %q", b.Bot.BotName)
	}
	if b.Alert.TitleDailyLaunch != "Daily lancé" {
		t.Fatalf("alert title %q", b.Alert.TitleDailyLaunch)
	}
}

func TestForLocale_EN(t *testing.T) {
	b := ForLocale(EN)
	if b.Alert.TitleDailyLaunch != "Daily started" {
		t.Fatalf("alert title %q", b.Alert.TitleDailyLaunch)
	}
	if b.Bot.BtnExtract() != "📥 Extract" {
		t.Fatalf("btn %q", b.Bot.BtnExtract())
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("TELEGRAM_LOCALE", "en")
	if FromEnv() != EN {
		t.Fatalf("got %q", FromEnv())
	}
}
