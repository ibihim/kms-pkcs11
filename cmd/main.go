package main

import (
	"fmt"
	"os"
)

func main() {
	if err := app(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s", err)
	}
}

func app() error {
	return nil
}
