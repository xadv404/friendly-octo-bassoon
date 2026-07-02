package main

import (
	"log"

	"github.com/sqli-hunter/sqli-hunter/internal/botapp"
)

func main() {
	if err := botapp.Run(); err != nil {
		log.Fatal(err)
	}
}
