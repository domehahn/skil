package main

import (
	"fmt"
	"os"

	"github.com/domehahn/skil/internal/evaltestadapter"
)

func main() {
	if err := evaltestadapter.Run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "assurance test adapter:", err)
		os.Exit(1)
	}
}
