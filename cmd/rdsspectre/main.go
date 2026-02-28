package main

import (
	"os"

	"github.com/ppiankov/rdsspectre/internal/commands"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := commands.Execute(version, commit, date); err != nil {
		os.Exit(1)
	}
}
