package main

import (
	"context"
	"os"

	"github.com/domehahn/skil/internal/cli"
)

func main() {
	app := cli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(context.Background(), os.Args[1:]))
}
