// Command scanner finds machines that are reachable from the internet and
// carry credentials worth stealing.
//
//	scanner [--fixtures dir] [--color auto|always|never]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"cloud-exposure-scanner/internal/collect"
	"cloud-exposure-scanner/internal/evaluate"
	"cloud-exposure-scanner/internal/report"
)

func main() {
	fixtures := flag.String("fixtures", "fixtures/demo", "directory of collected API responses")
	color := flag.String("color", "auto", "color in the output: auto, always or never")
	flag.Parse()

	snapshot, err := collect.FixtureCollector{Dir: *fixtures}.Collect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "scanner:", err)
		os.Exit(2)
	}
	results := evaluate.Evaluate(snapshot)
	report.Text(os.Stdout, filepath.Base(filepath.Clean(*fixtures)), results, useColor(*color))
}

func useColor(mode string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
