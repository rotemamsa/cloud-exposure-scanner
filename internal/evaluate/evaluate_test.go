package evaluate

import (
	"encoding/json"
	"strings"
	"testing"

	"cloud-exposure-scanner/internal/aws"
	"cloud-exposure-scanner/internal/collect"
)

func load(t *testing.T, dir string) *collect.Snapshot {
	t.Helper()
	s, err := collect.FixtureCollector{Dir: "../../fixtures/" + dir}.Collect()
	if err != nil {
		t.Fatalf("collect %s: %v", dir, err)
	}
	return s
}

func byName(t *testing.T, results []Result, name string) Result {
	t.Helper()
	for _, r := range results {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no result for %s", name)
	return Result{}
}

func stepStatus(r Result, name string) Status {
	for _, st := range r.Steps {
		if st.Name == name {
			return st.Status
		}
	}
	return ""
}

func TestDemoEnvironment(t *testing.T) {
	results := Evaluate(load(t, "demo"))

	tests := []struct {
		name        string
		verdict     Verdict
		severity    string
		blockedStep string
	}{
		{name: "payments-api", verdict: Finding, severity: "critical"},
		{name: "bastion", verdict: Finding, severity: "high"},
		// Same open security group as bastion and same role as payments-api.
		{name: "batch-worker", verdict: NoFinding, blockedStep: "public address"},
		// Reachable, but the role can only write logs.
		{name: "docs-site", verdict: NoFinding, blockedStep: "role"},
		// Open security group and an admin role, but the network ACL denies the port.
		{name: "legacy-admin", verdict: NoFinding, blockedStep: "network ACL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := byName(t, results, tt.name)
			if r.Verdict != tt.verdict {
				t.Fatalf("verdict = %s, want %s (%s)", r.Verdict, tt.verdict, r.Summary)
			}
			if r.Severity != tt.severity {
				t.Errorf("severity = %q, want %q", r.Severity, tt.severity)
			}
			if tt.blockedStep != "" && stepStatus(r, tt.blockedStep) != Blocked {
				t.Errorf("step %q = %s, want blocked", tt.blockedStep, stepStatus(r, tt.blockedStep))
			}
			if tt.verdict == Finding {
				if len(r.Fix) == 0 || len(r.Path) == 0 || r.Needs == "" {
					t.Errorf("finding is missing path, needs or remediation: %+v", r)
				}
				for _, st := range r.Steps {
					if st.Source == nil {
						t.Errorf("step %q has no source reference", st.Name)
					}
				}
			}
		})
	}

	if results[0].Name != "payments-api" {
		t.Errorf("critical finding should be listed first, got %s", results[0].Name)
	}
}

func TestMissingPermissionIsCannotTellNotNoFinding(t *testing.T) {
	results := Evaluate(load(t, "missing-permission"))

	tests := []struct {
		name    string
		verdict Verdict
	}{
		{"payments-api", Inconclusive},
		{"bastion", Inconclusive},
		// Still certain without route data, because another step blocks them.
		{"batch-worker", NoFinding},
		{"docs-site", NoFinding},
		{"legacy-admin", NoFinding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := byName(t, results, tt.name)
			if r.Verdict != tt.verdict {
				t.Fatalf("verdict = %s, want %s", r.Verdict, tt.verdict)
			}
			if tt.verdict != Inconclusive {
				return
			}
			if len(r.Missing) != 1 || r.Missing[0] != collect.APIRouteTables {
				t.Errorf("missing = %v, want [%s]", r.Missing, collect.APIRouteTables)
			}
			if r.Severity != "" {
				t.Errorf("an inconclusive result must not carry a severity, got %q", r.Severity)
			}
		})
	}
}

func TestOneChangeFlipsTheVerdict(t *testing.T) {
	// each applies a change to the machine with that name.
	each := func(s *collect.Snapshot, name string, change func(in *aws.Instance)) {
		n := 0
		for i := range s.Instances {
			if s.Instances[i].Name() == name {
				change(&s.Instances[i])
				n++
			}
		}
		if n == 0 {
			t.Fatalf("no instance %s", name)
		}
	}

	tests := []struct {
		name     string
		machine  string
		change   func(s *collect.Snapshot)
		verdict  Verdict
		severity string
	}{
		{
			name:    "enforcing IMDSv2 lowers payments-api to high",
			machine: "payments-api",
			change: func(s *collect.Snapshot) {
				each(s, "payments-api", func(in *aws.Instance) { in.MetadataOptions.HTTPTokens = "required" })
			},
			verdict:  Finding,
			severity: "high",
		},
		{
			name:    "removing the public address makes payments-api no finding",
			machine: "payments-api",
			change:  func(s *collect.Snapshot) { each(s, "payments-api", func(in *aws.Instance) { in.PublicIPAddress = "" }) },
			verdict: NoFinding,
		},
		{
			name:    "detaching the role makes bastion no finding",
			machine: "bastion",
			change:  func(s *collect.Snapshot) { each(s, "bastion", func(in *aws.Instance) { in.IamInstanceProfile = nil }) },
			verdict: NoFinding,
		},
		{
			name:    "dropping the deny rule exposes legacy-admin",
			machine: "legacy-admin",
			change: func(s *collect.Snapshot) {
				for i := range s.NetworkACLs {
					var kept []aws.NetworkACLEntry
					for _, e := range s.NetworkACLs[i].Entries {
						if e.RuleNumber != 90 {
							kept = append(kept, e)
						}
					}
					// Rule 100 only allows 443, so widen it to all TCP to let 22 through.
					for j := range kept {
						if kept[j].RuleNumber == 100 && !kept[j].Egress {
							kept[j].PortRange = nil
						}
					}
					s.NetworkACLs[i].Entries = kept
				}
			},
			verdict:  Finding,
			severity: "critical",
		},
		{
			name:    "a security group missing from the data makes bastion inconclusive",
			machine: "bastion",
			change:  func(s *collect.Snapshot) { s.SecurityGroups = s.SecurityGroups[:1] },
			verdict: Inconclusive,
		},
		{
			name:    "unreadable IAM data makes bastion inconclusive",
			machine: "bastion",
			change:  func(s *collect.Snapshot) { s.MarkMissing(collect.APIIAM, "AccessDenied") },
			verdict: Inconclusive,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := load(t, "demo")
			tt.change(s)
			r := byName(t, Evaluate(s), tt.machine)
			if r.Verdict != tt.verdict || r.Severity != tt.severity {
				t.Fatalf("got %s %q, want %s %q (%s)", r.Verdict, r.Severity, tt.verdict, tt.severity, r.Summary)
			}
		})
	}
}

func TestNetworkACLFirstMatchWins(t *testing.T) {
	port22 := &struct {
		From int `json:"From"`
		To   int `json:"To"`
	}{22, 22}
	entries := []aws.NetworkACLEntry{
		{RuleNumber: 200, Protocol: "-1", RuleAction: "allow", CidrBlock: world},
		{RuleNumber: 90, Protocol: "6", RuleAction: "deny", CidrBlock: world, PortRange: port22},
	}
	if ok, rule := decide(entries, false, 22); ok || rule != 90 {
		t.Errorf("port 22: allowed=%v by rule %d, want denied by rule 90", ok, rule)
	}
	if ok, rule := decide(entries, false, 443); !ok || rule != 200 {
		t.Errorf("port 443: allowed=%v by rule %d, want allowed by rule 200", ok, rule)
	}
	if ok, _ := decide(nil, false, 443); ok {
		t.Error("no matching rule must mean deny")
	}
}

func TestActionPatternMatch(t *testing.T) {
	tests := []struct {
		pattern, action string
		want            bool
	}{
		{"ssm:GetParameter*", "ssm:GetParametersByPath", true},
		{"s3:*", "s3:GetObject", true},
		{"S3:getobject", "s3:GetObject", true},
		{"s3:PutObject", "s3:GetObject", false},
		{"logs:*", "s3:GetObject", false},
	}
	for _, tt := range tests {
		if got := match(tt.pattern, tt.action); got != tt.want {
			t.Errorf("match(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
		}
	}
}

func TestSingleObjectStatementIsRead(t *testing.T) {
	var doc aws.PolicyDocument
	if err := json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`), &doc); err != nil {
		t.Fatalf("a single-object Statement must parse: %v", err)
	}
	if len(doc.Statement) != 1 || doc.Statement[0].Action[0] != "*" {
		t.Fatalf("statements = %+v", doc.Statement)
	}
}

// AmazonSSMManagedInstanceCore is the AWS managed policy most machines carry
// so Systems Manager can reach them. It allows reading parameters on every
// resource, so the role step counts it as access to secrets. That is a known
// source of noise, listed in the README.
func TestSSMManagedPolicyCountsAsSecrets(t *testing.T) {
	const arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
	var doc aws.PolicyDocument
	if err := json.Unmarshal([]byte(`{"Statement":[{"Effect":"Allow","Action":["ssm:DescribeAssociation","ssm:GetParameter","ssm:GetParameters","ssm:UpdateInstanceInformation"],"Resource":"*"}]}`), &doc); err != nil {
		t.Fatal(err)
	}
	s := load(t, "demo")
	policy := aws.ManagedPolicy{Arn: arn}
	if err := json.Unmarshal([]byte(`{"PolicyVersionList":[{"IsDefaultVersion":true}]}`), &policy); err != nil {
		t.Fatal(err)
	}
	policy.PolicyVersionList[0].Document = doc
	s.Policies = append(s.Policies, policy)

	var role aws.RoleDetail
	if err := json.Unmarshal([]byte(`{"RoleName":"ssm-only","AttachedManagedPolicies":[{"PolicyName":"AmazonSSMManagedInstanceCore","PolicyArn":"`+arn+`"}]}`), &role); err != nil {
		t.Fatal(err)
	}
	caps, unread := capabilities(s, &role)
	if len(unread) != 0 {
		t.Fatalf("policy not read: %v", unread)
	}
	if len(caps) == 0 || caps[0].Kind != "secrets" {
		t.Fatalf("capabilities = %+v, want secrets from ssm:GetParameter", caps)
	}
}

func TestRouteToTransitGatewayNamesTheTarget(t *testing.T) {
	s := load(t, "demo")
	for i := range s.RouteTables {
		for j := range s.RouteTables[i].Routes {
			if s.RouteTables[i].Routes[j].GatewayID == "igw-0d44444444444444d" {
				s.RouteTables[i].Routes[j].GatewayID = ""
				s.RouteTables[i].Routes[j].TransitGatewayID = "tgw-0a1b2c3d4e5f67890"
			}
		}
	}
	r := byName(t, Evaluate(s), "bastion")
	if stepStatus(r, "route") != Blocked {
		t.Fatalf("route status = %s, want blocked", stepStatus(r, "route"))
	}
	for _, st := range r.Steps {
		if st.Name == "route" && !strings.Contains(st.Detail, "tgw-0a1b2c3d4e5f67890") {
			t.Errorf("route evidence does not name the transit gateway: %q", st.Detail)
		}
	}
}
