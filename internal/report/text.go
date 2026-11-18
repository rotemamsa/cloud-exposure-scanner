// Package report prints the scan results in the terminal.
package report

import (
	"fmt"
	"io"
	"strings"

	"cloud-exposure-scanner/internal/evaluate"
)

type palette struct{ on bool }

func (p palette) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (p palette) bold(s string) string   { return p.wrap("1", s) }
func (p palette) dim(s string) string    { return p.wrap("2", s) }
func (p palette) red(s string) string    { return p.wrap("1;31", s) }
func (p palette) green(s string) string  { return p.wrap("32", s) }
func (p palette) yellow(s string) string { return p.wrap("1;33", s) }
func (p palette) cyan(s string) string   { return p.wrap("36", s) }

func (p palette) badge(r evaluate.Result) string {
	switch {
	case r.Verdict == evaluate.Finding && r.Severity == "critical":
		return p.wrap("1;97;41", " FINDING · CRITICAL ")
	case r.Verdict == evaluate.Finding:
		return p.wrap("1;30;48;5;208", " FINDING · HIGH ")
	case r.Verdict == evaluate.Inconclusive:
		return p.wrap("1;30;43", " CANNOT TELL ")
	}
	return p.wrap("1;30;42", " NO FINDING ")
}

func (p palette) status(s evaluate.Status) string {
	switch s {
	case evaluate.Open:
		return p.red(fmt.Sprintf("%-*s", statusCol, "✕ open"))
	case evaluate.Blocked:
		return p.green(fmt.Sprintf("%-*s", statusCol, "✓ blocked"))
	case evaluate.Unknown:
		return p.yellow(fmt.Sprintf("%-*s", statusCol, "? unknown"))
	}
	return p.dim(fmt.Sprintf("%-*s", statusCol, "· skipped"))
}

// verdict is the short verdict text for the summary table.
func (p palette) verdict(r evaluate.Result) string {
	switch {
	case r.Verdict == evaluate.Finding && r.Severity == "critical":
		return p.red("FINDING · CRITICAL")
	case r.Verdict == evaluate.Finding:
		return p.wrap("1;38;5;208", "FINDING · HIGH")
	case r.Verdict == evaluate.Inconclusive:
		return p.yellow("CANNOT TELL")
	}
	return p.green("NO FINDING")
}

// Text writes the report in three parts: one table with every machine and
// every step, a short list of the machines that are not findings and why, and
// a block per finding with the evidence and the fix.
func Text(w io.Writer, environment string, results []evaluate.Result, color bool) {
	p := palette{on: color}
	rule := p.dim(strings.Repeat("─", width))

	var findings, quiet, inconclusive int
	var missing []string
	for _, r := range results {
		switch r.Verdict {
		case evaluate.Finding:
			findings++
		case evaluate.Inconclusive:
			inconclusive++
		default:
			quiet++
		}
		for _, m := range r.Missing {
			if !contains(missing, m) {
				missing = append(missing, m)
			}
		}
	}

	// Part 1: every machine against the five steps.
	fmt.Fprintf(w, "\n  %s  %s\n\n", p.bold("CLOUD EXPOSURE SCAN"), p.dim(environment))
	header := fmt.Sprintf("%-*s", nameCol, "MACHINE")
	for _, h := range []string{"FIREWALL", "ADDRESS", "ROUTE", "ACL", "ROLE"} {
		header += fmt.Sprintf("%-*s", statusCol, h)
	}
	fmt.Fprintf(w, "  %s\n", p.dim(header+"VERDICT"))
	for _, r := range results {
		fmt.Fprintf(w, "  %-*s", nameCol, r.Name)
		for _, st := range r.Steps {
			fmt.Fprint(w, p.status(st.Status))
		}
		fmt.Fprintf(w, "%s\n", p.verdict(r))
	}
	fmt.Fprintf(w, "\n  %s   %s   %s\n",
		p.red(plural(findings, "finding", "findings")),
		p.green(fmt.Sprintf("%d no finding", quiet)),
		p.yellow(fmt.Sprintf("%d cannot tell", inconclusive)))
	if len(missing) > 0 {
		fmt.Fprintf(w, "  %s %s\n", p.yellow("The scanner could not read:"), strings.Join(missing, ", "))
	}

	// Part 2: the machines that are not findings, one short reason each.
	if quiet > 0 {
		fmt.Fprintf(w, "\n%s\n  %s\n\n", rule, p.green("NO FINDING, AND WHY"))
		for _, r := range results {
			if r.Verdict == evaluate.NoFinding {
				fmt.Fprintf(w, "  %-*s%s\n", nameCol, r.Name, wrap(reason(r, results), 2+nameCol))
			}
		}
	}

	// Part 3: one block per finding, and per machine the scanner could not judge.
	for _, r := range results {
		if r.Verdict == evaluate.NoFinding {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", rule)
		fmt.Fprintf(w, "  %s  %s  %s\n\n", p.badge(r), p.bold(r.Name), p.dim(r.InstanceID))

		row := func(label, text string) {
			if text != "" {
				fmt.Fprintf(w, "  %s%s\n", p.bold(fmt.Sprintf("%-*s", labelCol, label)), wrap(text, 2+labelCol))
			}
		}
		row("WHY", r.Summary)
		row("WORST", r.WorstCase)
		row("PATH", strings.Join(r.Path, " → "))
		row("NEEDS", r.Needs)

		fmt.Fprintf(w, "\n  %s\n", p.dim(fmt.Sprintf("%-*s%s", stepCol, "STEP", "EVIDENCE")))
		var sources []string
		for _, st := range r.Steps {
			fmt.Fprintf(w, "  %-*s%s\n", stepCol, st.Name, wrap(st.Detail, 2+stepCol))
			if st.Source != nil {
				sources = append(sources, fmt.Sprintf("%s:%d", st.Source.File, st.Source.Line))
			}
		}
		if len(sources) > 0 {
			fmt.Fprintf(w, "  %-*s%s\n", stepCol, "read from", p.dim(wrap(strings.Join(sources, ", "), 2+stepCol)))
		}

		if len(r.Controls) > 0 {
			fmt.Fprintf(w, "\n  %s\n", p.dim(fmt.Sprintf("%-*s%-*s%s", controlCol, "OTHER CONTROL", statusCol, "STATUS", "NOTE")))
			for _, ctl := range r.Controls {
				mark := p.red(fmt.Sprintf("%-*s", statusCol, "✕ missing"))
				if ctl.InPlace {
					mark = p.green(fmt.Sprintf("%-*s", statusCol, "✓ in place"))
				}
				fmt.Fprintf(w, "  %-*s%s%s\n", controlCol, ctl.Name, mark, wrap(capitalize(ctl.Note), 2+controlCol+statusCol))
			}
		}
		if len(r.Fix) > 0 {
			fmt.Fprintf(w, "\n  %s\n", p.dim("REMEDIATION"))
			for i, f := range r.Fix {
				fmt.Fprintf(w, "  %d. %s\n", i+1, wrap(f, 5))
			}
		}
	}
	fmt.Fprintf(w, "\n%s\n\n", rule)
}

// reason explains a no-finding result: each step that blocks the path, where
// that was read, and the finding it looks like.
func reason(r evaluate.Result, all []evaluate.Result) string {
	var parts []string
	for _, st := range r.Steps {
		if st.Status != evaluate.Blocked {
			continue
		}
		text := fmt.Sprintf("Blocked at %s: %s", st.Name, st.Detail)
		if st.Source != nil {
			text += fmt.Sprintf(" (%s:%d)", st.Source.File, st.Source.Line)
		}
		parts = append(parts, text+".")
	}
	if len(r.Steps) > 0 && r.Steps[0].Status == evaluate.Open {
		for _, f := range all {
			if f.Verdict == evaluate.Finding && f.Steps[0].Detail == r.Steps[0].Detail {
				parts = append(parts, fmt.Sprintf("Same open firewall rule as %s.", f.Name))
				break
			}
		}
	}
	return strings.Join(parts, " ")
}

// Column widths. width is the widest line the report prints.
const (
	width      = 96
	nameCol    = 15
	labelCol   = 9
	stepCol    = 16
	statusCol  = 12
	controlCol = 22
)

// wrap breaks text at word boundaries so no line passes width. Lines after the
// first are indented to the column where the text started.
func wrap(text string, indent int) string {
	var out strings.Builder
	col := indent
	for i, word := range strings.Fields(text) {
		n := len([]rune(word))
		switch {
		case i == 0:
		case col+1+n > width:
			out.WriteString("\n" + strings.Repeat(" ", indent))
			col = indent
		default:
			out.WriteString(" ")
			col++
		}
		out.WriteString(word)
		col += n
	}
	return out.String()
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
