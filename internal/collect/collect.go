// Package collect turns cloud API responses into one Snapshot.
//
// The proof of concept reads JSON files. A live collector would make the same
// read-only API calls and fill the same Snapshot, so the evaluator does not
// know or care where the data came from.
package collect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"cloud-exposure-scanner/internal/aws"
)

// The read-only API calls the check depends on.
const (
	APIInstances      = "ec2:DescribeInstances"
	APISecurityGroups = "ec2:DescribeSecurityGroups"
	APIRouteTables    = "ec2:DescribeRouteTables"
	APINetworkACLs    = "ec2:DescribeNetworkAcls"
	APIIAM            = "iam:GetAccountAuthorizationDetails"
)

// Ref points at the place in the collected data that backs a statement.
type Ref struct {
	File string
	Line int
}

type source struct {
	file string
	raw  []byte
	err  string
}

// Snapshot is everything collected from one environment, plus a record of
// which API calls did not return data.
type Snapshot struct {
	Instances      []aws.Instance
	SecurityGroups []aws.SecurityGroup
	RouteTables    []aws.RouteTable
	NetworkACLs    []aws.NetworkACL
	Roles          []aws.RoleDetail
	Policies       []aws.ManagedPolicy

	sources map[string]*source
}

// NewSnapshot returns an empty snapshot.
func NewSnapshot() *Snapshot {
	return &Snapshot{sources: map[string]*source{}}
}

// MarkMissing records that an API call returned no usable data, and why.
func (s *Snapshot) MarkMissing(api, reason string) {
	next := &source{err: reason}
	if src := s.sources[api]; src != nil {
		next.file, next.raw = src.file, src.raw
	}
	s.sources[api] = next
}

// Missing reports whether the data of an API call is absent, and the reason.
// Absent data is never treated as "nothing there".
func (s *Snapshot) Missing(api string) (string, bool) {
	if src := s.sources[api]; src != nil && src.err != "" {
		return src.err, true
	}
	return "", false
}

// Ref finds the first line in the raw response of an API call that holds the
// given value, so every evidence line can cite its source.
func (s *Snapshot) Ref(api, value string) *Ref {
	src := s.sources[api]
	if src == nil || src.raw == nil || value == "" {
		return nil
	}
	idx := bytes.Index(src.raw, []byte(`"`+value+`"`))
	if idx < 0 {
		return nil
	}
	return &Ref{File: src.file, Line: 1 + bytes.Count(src.raw[:idx], []byte("\n"))}
}

// FixtureCollector reads one directory of JSON files. Each file is named after
// the API call it stands for and has the shape of that call's response.
type FixtureCollector struct {
	Dir string
}

// Files maps each API call to its fixture file name.
var Files = map[string]string{
	APIInstances:      "ec2-describe-instances.json",
	APISecurityGroups: "ec2-describe-security-groups.json",
	APIRouteTables:    "ec2-describe-route-tables.json",
	APINetworkACLs:    "ec2-describe-network-acls.json",
	APIIAM:            "iam-get-account-authorization-details.json",
}

// Collect loads the fixture directory into a Snapshot.
func (c FixtureCollector) Collect() (*Snapshot, error) {
	s := NewSnapshot()

	var instances struct {
		Reservations []struct {
			Instances []aws.Instance `json:"Instances"`
		} `json:"Reservations"`
	}
	var groups struct {
		SecurityGroups []aws.SecurityGroup `json:"SecurityGroups"`
	}
	var routes struct {
		RouteTables []aws.RouteTable `json:"RouteTables"`
	}
	var acls struct {
		NetworkACLs []aws.NetworkACL `json:"NetworkAcls"`
	}
	var iam struct {
		RoleDetailList []aws.RoleDetail    `json:"RoleDetailList"`
		Policies       []aws.ManagedPolicy `json:"Policies"`
	}

	targets := []struct {
		api  string
		into any
	}{
		{APIInstances, &instances},
		{APISecurityGroups, &groups},
		{APIRouteTables, &routes},
		{APINetworkACLs, &acls},
		{APIIAM, &iam},
	}
	for _, t := range targets {
		if err := c.load(s, t.api, t.into); err != nil {
			return nil, err
		}
	}
	if reason, missing := s.Missing(APIInstances); missing {
		return nil, fmt.Errorf("%s is required to list machines: %s", APIInstances, reason)
	}

	for _, r := range instances.Reservations {
		s.Instances = append(s.Instances, r.Instances...)
	}
	s.SecurityGroups = groups.SecurityGroups
	s.RouteTables = routes.RouteTables
	s.NetworkACLs = acls.NetworkACLs
	s.Roles = iam.RoleDetailList
	s.Policies = iam.Policies
	return s, nil
}

// load reads one fixture file. A missing file or an AWS error body is recorded
// as missing data. Only a file that cannot be parsed at all is a hard error.
func (c FixtureCollector) load(s *Snapshot, api string, into any) error {
	name := Files[api]
	raw, err := os.ReadFile(filepath.Join(c.Dir, name))
	if errors.Is(err, os.ErrNotExist) {
		s.MarkMissing(api, "not collected")
		return nil
	}
	if err != nil {
		return err
	}
	s.sources[api] = &source{file: name, raw: raw}

	var envelope struct {
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if envelope.Error != nil {
		s.MarkMissing(api, envelope.Error.Code)
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// MissingAPIs lists the API calls that returned no usable data.
func (s *Snapshot) MissingAPIs() []string {
	var out []string
	for api, src := range s.sources {
		if src.err != "" {
			out = append(out, api)
		}
	}
	sort.Strings(out)
	return out
}
