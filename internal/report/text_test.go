package report

import (
	"bytes"
	"strings"
	"testing"

	"cloud-exposure-scanner/internal/collect"
	"cloud-exposure-scanner/internal/evaluate"
)

func render(t *testing.T, fixtures string) string {
	t.Helper()
	s, err := collect.FixtureCollector{Dir: "../../fixtures/" + fixtures}.Collect()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	Text(&out, fixtures, evaluate.Evaluate(s), false)
	return out.String()
}

func TestNoLineIsWiderThanTheReport(t *testing.T) {
	for _, fixtures := range []string{"demo", "missing-permission"} {
		for i, line := range strings.Split(render(t, fixtures), "\n") {
			if n := len([]rune(line)); n > width {
				t.Errorf("%s line %d is %d wide, want at most %d: %q", fixtures, i+1, n, width, line)
			}
		}
	}
}

func TestNoFindingNamesTheBlockingStepAndTheSimilarFinding(t *testing.T) {
	out := strings.Join(strings.Fields(render(t, "demo")), " ")
	for _, want := range []string{
		"Blocked at public address: the machine has no public address (ec2-describe-instances.json:65).",
		"Blocked at role: docs-site-role grants nothing sensitive",
		"Blocked at network ACL: acl-0a2222222222222bb rule 90 denies tcp/22 from 0.0.0.0/0",
		"Same open firewall rule as bastion.",
		"Same open firewall rule as payments-api.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestSummaryTableListsEveryMachineOnce(t *testing.T) {
	summary := strings.SplitN(render(t, "demo"), strings.Repeat("─", width), 2)[0]
	for _, name := range []string{"payments-api", "bastion", "batch-worker", "docs-site", "legacy-admin"} {
		if n := strings.Count(summary, "  "+name+" "); n != 1 {
			t.Errorf("%s appears %d times in the summary table, want 1", name, n)
		}
	}
}

func TestMissingPermissionIsNamedAtTheTop(t *testing.T) {
	out := render(t, "missing-permission")
	if !strings.Contains(out, "The scanner could not read: ec2:DescribeRouteTables") {
		t.Error("the missing permission is not named in the summary")
	}
	if strings.Contains(out, "FINDING · ") {
		t.Error("a machine whose route could not be read was reported as a finding")
	}
}
