// Package evaluate decides, for each machine, whether someone on the internet
// can reach it and walk away with credentials that open something valuable.
//
// The check walks five steps. A finding needs all five to be open. One blocked
// step makes it no finding. One step that could not be read makes it inconclusive.
// It never guesses.
package evaluate

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"cloud-exposure-scanner/internal/aws"
	"cloud-exposure-scanner/internal/collect"
)

// Verdict is the answer for one machine.
type Verdict string

// The three possible answers.
const (
	Finding      Verdict = "finding"
	NoFinding    Verdict = "no_finding"
	Inconclusive Verdict = "inconclusive"
)

// Status is the state of one step on the route.
type Status string

// Open means an attacker gets past this step. Blocked means they do not.
const (
	Open    Status = "open"
	Blocked Status = "blocked"
	Unknown Status = "unknown"
	Skipped Status = "skipped"
)

// Step is one hop of the route, with the evidence behind its status.
type Step struct {
	Name       string
	Status     Status
	Detail     string
	Source     *collect.Ref
	MissingAPI string
}

// Capability is one valuable thing the machine's role is allowed to do.
type Capability struct {
	Kind     string
	Action   string
	Resource string
	Policy   string
}

// Control is a protection the check looked for, found or not.
type Control struct {
	Name    string
	InPlace bool
	Note    string
}

// Result is the full answer for one machine.
type Result struct {
	InstanceID string
	Name       string
	Verdict    Verdict
	Severity   string
	Summary    string
	Path       []string
	Needs      string
	Steps      []Step
	Controls   []Control
	Fix        []string
	Missing    []string
	WorstCase  string
}

const world = "0.0.0.0/0"

// Evaluate checks every running machine in the snapshot.
func Evaluate(s *collect.Snapshot) []Result {
	var out []Result
	for _, in := range s.Instances {
		if in.State.Name != "" && in.State.Name != "running" {
			continue
		}
		out = append(out, evaluateInstance(s, in))
	}
	sort.SliceStable(out, func(a, b int) bool { return rank(out[a]) < rank(out[b]) })
	return out
}

func rank(r Result) int {
	switch {
	case r.Verdict == Finding && r.Severity == "critical":
		return 0
	case r.Verdict == Finding:
		return 1
	case r.Verdict == Inconclusive:
		return 2
	}
	return 3
}

func evaluateInstance(s *collect.Snapshot, in aws.Instance) Result {
	r := Result{InstanceID: in.InstanceID, Name: in.Name()}

	open, firewall := firewallStep(s, in)
	address := addressStep(s, in)
	route := routeStep(s, in)
	reachable, acl := aclStep(s, in, open, firewall.Status)
	role, caps, roleStep := roleStep(s, in)
	r.Steps = []Step{firewall, address, route, acl, roleStep}

	var blocked, unknown []Step
	for _, st := range r.Steps {
		switch st.Status {
		case Blocked:
			blocked = append(blocked, st)
		case Unknown:
			unknown = append(unknown, st)
		}
	}

	imdsV2 := in.MetadataOptions.HTTPTokens == "required"
	switch {
	case len(blocked) > 0:
		r.Verdict = NoFinding
		r.Summary = noFindingSummary(blocked[0].Name)
	case len(unknown) > 0:
		r.Verdict = Inconclusive
		var steps []string
		for _, st := range unknown {
			steps = append(steps, st.Name)
			if st.MissingAPI != "" {
				r.Missing = appendUnique(r.Missing, st.MissingAPI)
				r.Fix = append(r.Fix, fmt.Sprintf("Check that the scanner role can call %s and that it returned this resource, then scan again.", st.MissingAPI))
			}
		}
		r.Summary = fmt.Sprintf("The %s step could not be read.", strings.Join(steps, " and "))
		if len(caps) > 0 {
			r.WorstCase = fmt.Sprintf("If that step is open, this is a %s finding.", severity(caps, imdsV2))
		}
	default:
		r.Verdict = Finding
		r.Severity = severity(caps, imdsV2)
		r.Summary = fmt.Sprintf("Reachable from the internet on %s. Its role %s can %s.",
			labels(reachable), role.RoleName, describe(caps))
		r.Path = []string{"internet", reachable[0].Group + " " + labels(reachable), r.Name, role.RoleName, loot(caps)}
		r.Needs = needs(reachable)
		r.Controls = controls(role, imdsV2)
		r.Fix = fixes(in, reachable, role, caps, imdsV2)
	}
	return r
}

// port is a TCP port range a security group opens to the whole internet.
type port struct {
	From, To int
	Group    string
}

func (p port) label() string {
	switch {
	case p.From == 0 && p.To == 65535:
		return "all TCP ports"
	case p.From == p.To:
		return fmt.Sprintf("tcp/%d", p.From)
	}
	return fmt.Sprintf("tcp/%d-%d", p.From, p.To)
}

func labels(ports []port) string {
	var out []string
	for _, p := range ports {
		out = appendUnique(out, p.label())
	}
	return strings.Join(out, ", ")
}

func unreadable(api, reason string) Step {
	return Step{Status: Unknown, MissingAPI: api, Detail: fmt.Sprintf("%s could not be read (%s)", api, reason)}
}

// Step 1. Does a security group let the whole IPv4 internet in on a TCP port?
func firewallStep(s *collect.Snapshot, in aws.Instance) ([]port, Step) {
	if reason, missing := s.Missing(collect.APISecurityGroups); missing {
		st := unreadable(collect.APISecurityGroups, reason)
		st.Name = "firewall"
		return nil, st
	}
	var open []port
	var notCollected []string
	for _, ref := range in.SecurityGroups {
		found := false
		for _, sg := range s.SecurityGroups {
			if sg.GroupID != ref.GroupID {
				continue
			}
			found = true
			for _, perm := range sg.IPPermissions {
				if perm.IPProtocol != "tcp" && perm.IPProtocol != "-1" {
					continue
				}
				fromWorld := false
				for _, r := range perm.IPRanges {
					fromWorld = fromWorld || r.CidrIP == world
				}
				if !fromWorld {
					continue
				}
				p := port{From: 0, To: 65535, Group: sg.GroupID}
				if perm.IPProtocol == "tcp" && perm.FromPort != nil && perm.ToPort != nil {
					p.From, p.To = *perm.FromPort, *perm.ToPort
				}
				open = append(open, p)
			}
		}
		if !found {
			notCollected = append(notCollected, ref.GroupID)
		}
	}
	st := Step{Name: "firewall", Source: s.Ref(collect.APIInstances, in.InstanceID)}
	if len(open) == 0 && len(notCollected) > 0 {
		// A group we never saw may be the one that opens the port.
		st.Status = Unknown
		st.MissingAPI = collect.APISecurityGroups
		st.Detail = "security group not in the collected data: " + strings.Join(notCollected, ", ")
		return nil, st
	}
	if len(open) == 0 {
		st.Status = Blocked
		st.Detail = "no security group rule lets the whole internet in"
		return nil, st
	}
	st.Status = Open
	st.Detail = fmt.Sprintf("%s allows %s from %s", open[0].Group, labels(open), world)
	st.Source = s.Ref(collect.APISecurityGroups, open[0].Group)
	return open, st
}

// Step 2. Does the machine have an address the internet can dial?
func addressStep(s *collect.Snapshot, in aws.Instance) Step {
	st := Step{Name: "public address", Source: s.Ref(collect.APIInstances, in.InstanceID)}
	if in.PublicIPAddress == "" {
		st.Status = Blocked
		st.Detail = "the machine has no public address"
		return st
	}
	st.Status = Open
	st.Detail = "public address " + in.PublicIPAddress
	return st
}

// Step 3. Does the subnet send traffic to an internet gateway?
func routeStep(s *collect.Snapshot, in aws.Instance) Step {
	if reason, missing := s.Missing(collect.APIRouteTables); missing {
		st := unreadable(collect.APIRouteTables, reason)
		st.Name = "route"
		return st
	}
	st := Step{Name: "route"}
	var table, main *aws.RouteTable
	for i := range s.RouteTables {
		t := &s.RouteTables[i]
		for _, a := range t.Associations {
			if a.SubnetID == in.SubnetID {
				table = t
			}
			if a.Main && t.VpcID == in.VpcID {
				main = t
			}
		}
	}
	if table == nil {
		table = main
	}
	if table == nil {
		st.Status = Unknown
		st.MissingAPI = collect.APIRouteTables
		st.Detail = "no route table found for subnet " + in.SubnetID
		return st
	}
	st.Source = s.Ref(collect.APIRouteTables, table.RouteTableID)
	st.Status = Blocked
	st.Detail = table.RouteTableID + " has no default route"
	for _, r := range table.Routes {
		if r.DestinationCidrBlock != world {
			continue
		}
		if strings.HasPrefix(r.GatewayID, "igw-") {
			st.Status = Open
			st.Detail = fmt.Sprintf("%s sends %s to %s", table.RouteTableID, world, r.GatewayID)
			return st
		}
		if r.NatGatewayID != "" {
			st.Detail = fmt.Sprintf("%s sends %s to %s, which accepts no inbound connections", table.RouteTableID, world, r.NatGatewayID)
			continue
		}
		// A transit gateway, peering connection or network appliance can lead
		// to an entry point in another network. That is outside this check, so
		// the step stays blocked here and the evidence says why.
		target := firstNonEmpty(r.TransitGatewayID, r.VpcPeeringID, r.NetworkInterfaceID, r.GatewayID, "an unknown target")
		st.Detail = fmt.Sprintf("%s sends %s to %s, not to an internet gateway. Entry points in other networks are not checked", table.RouteTableID, world, target)
	}
	return st
}

// Step 4. Does the subnet's network ACL let the open port in and replies out?
func aclStep(s *collect.Snapshot, in aws.Instance, open []port, firewall Status) ([]port, Step) {
	st := Step{Name: "network ACL"}
	if len(open) == 0 {
		st.Status = Skipped
		st.Detail = "no open port to test"
		if firewall == Unknown {
			st.Status = Unknown
			st.Detail = "depends on the firewall step"
		}
		return nil, st
	}
	if reason, missing := s.Missing(collect.APINetworkACLs); missing {
		st = unreadable(collect.APINetworkACLs, reason)
		st.Name = "network ACL"
		return nil, st
	}
	var acl *aws.NetworkACL
	for i := range s.NetworkACLs {
		for _, a := range s.NetworkACLs[i].Associations {
			if a.SubnetID == in.SubnetID {
				acl = &s.NetworkACLs[i]
			}
		}
	}
	if acl == nil {
		st.Status = Unknown
		st.MissingAPI = collect.APINetworkACLs
		st.Detail = "no network ACL found for subnet " + in.SubnetID
		return nil, st
	}
	st.Source = s.Ref(collect.APINetworkACLs, acl.NetworkACLID)

	// Replies leave on a high port, so outbound is tested on one of those.
	outOK, outRule := decide(acl.Entries, true, 49152)
	var reachable []port
	var why string
	for _, p := range open {
		inOK, inRule := decide(acl.Entries, false, p.From)
		switch {
		case inOK && outOK:
			reachable = append(reachable, p)
			why = fmt.Sprintf("%s %s allows %s in, %s allows replies out", acl.NetworkACLID, ruleName(inRule), p.label(), ruleName(outRule))
		case !inOK && why == "":
			why = fmt.Sprintf("%s %s denies %s from %s", acl.NetworkACLID, ruleName(inRule), p.label(), world)
		case why == "":
			why = fmt.Sprintf("%s %s denies replies going out", acl.NetworkACLID, ruleName(outRule))
		}
	}
	st.Detail = why
	st.Status = Blocked
	if len(reachable) > 0 {
		st.Status = Open
	}
	return reachable, st
}

// decide applies network ACL rules the way AWS does: lowest number first, the
// first rule that matches wins, and no match means deny.
func decide(entries []aws.NetworkACLEntry, egress bool, tcpPort int) (bool, int) {
	sorted := append([]aws.NetworkACLEntry(nil), entries...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].RuleNumber < sorted[b].RuleNumber })
	for _, e := range sorted {
		if e.Egress != egress || e.CidrBlock != world {
			continue
		}
		if e.Protocol != "6" && e.Protocol != "-1" {
			continue
		}
		if e.Protocol == "6" && e.PortRange != nil && (tcpPort < e.PortRange.From || tcpPort > e.PortRange.To) {
			continue
		}
		return e.RuleAction == "allow", e.RuleNumber
	}
	return false, 0
}

func ruleName(n int) string {
	if n == 0 || n == 32767 {
		return "default rule"
	}
	return fmt.Sprintf("rule %d", n)
}

// Step 5. Do the machine's credentials open anything worth stealing?
func roleStep(s *collect.Snapshot, in aws.Instance) (*aws.RoleDetail, []Capability, Step) {
	st := Step{Name: "role", Source: s.Ref(collect.APIInstances, in.InstanceID)}
	if in.IamInstanceProfile == nil {
		st.Status = Blocked
		st.Detail = "no role is attached, so there are no credentials to steal"
		return nil, nil, st
	}
	if reason, missing := s.Missing(collect.APIIAM); missing {
		st = unreadable(collect.APIIAM, reason)
		st.Name = "role"
		return nil, nil, st
	}
	var role *aws.RoleDetail
	for i := range s.Roles {
		for _, p := range s.Roles[i].InstanceProfileList {
			if p.Arn == in.IamInstanceProfile.Arn {
				role = &s.Roles[i]
			}
		}
	}
	if role == nil {
		st.Status = Unknown
		st.MissingAPI = collect.APIIAM
		st.Detail = "instance profile not found in the IAM data: " + in.IamInstanceProfile.Arn
		return nil, nil, st
	}
	st.Source = s.Ref(collect.APIIAM, role.RoleName)

	caps, unread := capabilities(s, role)
	switch {
	case len(caps) > 0:
		c := caps[0]
		st.Status = Open
		st.Detail = fmt.Sprintf("%s allows %s on %s (policy %s)", role.RoleName, c.Action, c.Resource, c.Policy)
		if len(caps) > 1 {
			st.Detail += fmt.Sprintf(", and %d more", len(caps)-1)
		}
	case len(unread) > 0:
		st.Status = Unknown
		st.MissingAPI = collect.APIIAM
		st.Detail = "policy document not collected: " + strings.Join(unread, ", ")
	default:
		st.Status = Blocked
		st.Detail = role.RoleName + " grants nothing sensitive"
	}
	return role, caps, st
}

// sensitive lists the actions that make stolen credentials valuable, most
// serious kind first.
var sensitive = []struct {
	kind    string
	actions []string
}{
	{"privilege escalation", []string{"iam:PassRole", "iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy", "iam:AttachUserPolicy", "iam:PutUserPolicy"}},
	{"secrets", []string{"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"}},
	{"data", []string{"s3:GetObject", "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query"}},
}

var kindOrder = map[string]int{"admin": 0, "privilege escalation": 1, "secrets": 2, "data": 3}

// capabilities reads every Allow statement on the role, inline and attached.
// It also returns attached policies whose document was not in the data.
func capabilities(s *collect.Snapshot, role *aws.RoleDetail) ([]Capability, []string) {
	type doc struct {
		name string
		doc  aws.PolicyDocument
	}
	var docs []doc
	var unread []string
	for _, p := range role.RolePolicyList {
		docs = append(docs, doc{p.PolicyName, p.PolicyDocument})
	}
	for _, att := range role.AttachedManagedPolicies {
		found := false
		for _, mp := range s.Policies {
			if mp.Arn != att.PolicyArn {
				continue
			}
			for _, v := range mp.PolicyVersionList {
				if v.IsDefaultVersion {
					docs = append(docs, doc{att.PolicyName, v.Document})
					found = true
				}
			}
		}
		if !found {
			unread = append(unread, att.PolicyName)
		}
	}

	var caps []Capability
	seen := map[string]bool{}
	add := func(c Capability) {
		key := c.Kind + "|" + c.Policy + "|" + c.Action
		if !seen[key] {
			seen[key] = true
			caps = append(caps, c)
		}
	}
	for _, d := range docs {
		for _, stmt := range d.doc.Statement {
			if stmt.Effect != "Allow" {
				continue
			}
			resource := strings.Join(stmt.Resource, ", ")
			for _, action := range stmt.Action {
				if action == "*" && contains(stmt.Resource, "*") {
					add(Capability{"admin", "*", "*", d.name})
					continue
				}
				for _, group := range sensitive {
					for _, target := range group.actions {
						if match(action, target) {
							add(Capability{group.kind, action, resource, d.name})
							break
						}
					}
				}
			}
		}
	}
	sort.SliceStable(caps, func(a, b int) bool { return kindOrder[caps[a].Kind] < kindOrder[caps[b].Kind] })
	return caps, unread
}

// match reports whether an IAM action pattern such as "ssm:Get*" covers a
// concrete action. IAM actions are not case sensitive.
func match(pattern, action string) bool {
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(action))
	return err == nil && ok
}

func kinds(caps []Capability) []string {
	var out []string
	for _, c := range caps {
		out = appendUnique(out, c.Kind)
	}
	return out
}

func describe(caps []Capability) string {
	phrase := map[string]string{
		"admin":                "administer the whole account",
		"privilege escalation": "raise itself to administrator",
		"secrets":              "read secrets",
		"data":                 "read stored data",
	}
	var out []string
	for _, k := range kinds(caps) {
		out = append(out, phrase[k])
	}
	return strings.Join(out, " and ")
}

func loot(caps []Capability) string {
	short := map[string]string{"admin": "full account", "privilege escalation": "admin rights", "secrets": "secrets", "data": "data"}
	var out []string
	for _, k := range kinds(caps) {
		out = append(out, short[k])
	}
	return strings.Join(out, ", ")
}

// severity is critical when the credentials lead to full control, or when the
// old metadata service makes them easy to steal. Otherwise it is high.
func severity(caps []Capability, imdsV2 bool) string {
	for _, c := range caps {
		if c.Kind == "admin" || c.Kind == "privilege escalation" {
			return "critical"
		}
	}
	if !imdsV2 {
		return "critical"
	}
	return "high"
}

func isAdminPort(p port) bool {
	return (p.From <= 22 && 22 <= p.To) || (p.From <= 3389 && 3389 <= p.To)
}

func needs(reachable []port) string {
	for _, p := range reachable {
		if isAdminPort(p) {
			return fmt.Sprintf("A weak login or an exploit on %s. No AWS credentials.", p.label())
		}
	}
	return fmt.Sprintf("An exploitable bug in the service on %s, such as request forgery or remote code execution. No AWS credentials.", reachable[0].label())
}

func controls(role *aws.RoleDetail, imdsV2 bool) []Control {
	imds := Control{Name: "IMDSv2 enforced", InPlace: imdsV2, Note: "HttpTokens is required, so a request forgery bug alone cannot read the credentials"}
	if !imdsV2 {
		imds.Note = "HttpTokens is optional, so a request forgery bug is enough to read the role credentials"
	}
	boundary := Control{Name: "Permissions boundary", InPlace: role.PermissionsBoundary != nil, Note: "none on " + role.RoleName + ", so nothing caps what the role can do"}
	if boundary.InPlace {
		boundary.Note = "present but not evaluated here, so the role may be able to do less than listed"
	}
	return []Control{imds, boundary}
}

func fixes(in aws.Instance, reachable []port, role *aws.RoleDetail, caps []Capability, imdsV2 bool) []string {
	var out []string
	for _, p := range reachable {
		if isAdminPort(p) {
			out = appendUnique(out, fmt.Sprintf("Close %s to the internet on %s. Use SSM Session Manager, or allow one known address range.", p.label(), p.Group))
		}
	}
	if !imdsV2 {
		out = append(out, fmt.Sprintf("Require IMDSv2 on %s: set HttpTokens to required and the hop limit to 1.", in.InstanceID))
	}
	for _, c := range caps {
		switch {
		case c.Kind == "admin":
			out = appendUnique(out, fmt.Sprintf("Replace %s on %s with a policy that lists only what this machine needs.", c.Policy, role.RoleName))
		case strings.Contains(c.Resource, "*") && !strings.Contains(c.Resource, ":"):
			out = appendUnique(out, fmt.Sprintf("Scope %s in policy %s to the resources this machine needs, not *.", c.Action, c.Policy))
		}
	}
	for _, p := range reachable {
		if !isAdminPort(p) {
			out = appendUnique(out, fmt.Sprintf("%s on %s looks intentional. Keep it open and shrink what the role can reach.", p.label(), p.Group))
		}
	}
	return out
}

func noFindingSummary(step string) string {
	switch step {
	case "firewall":
		return "Not reachable. No port is open to the internet."
	case "public address":
		return "Not reachable. The machine has no public address."
	case "route":
		return "Not reachable. Its subnet has no route from the internet."
	case "network ACL":
		return "Not reachable. The network ACL blocks the open port."
	}
	return "Reachable, but its credentials open nothing worth stealing."
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func appendUnique(list []string, v string) []string {
	if contains(list, v) {
		return list
	}
	return append(list, v)
}
