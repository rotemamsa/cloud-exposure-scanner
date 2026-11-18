// Package aws holds the subset of AWS API response shapes the scanner reads.
// Field names and nesting match the real API output, so a fixture file and a
// live response decode into the same types.
package aws

import "encoding/json"

// Instance is one entry of ec2:DescribeInstances.
type Instance struct {
	InstanceID string `json:"InstanceId"`
	State      struct {
		Name string `json:"Name"`
	} `json:"State"`
	VpcID           string `json:"VpcId"`
	SubnetID        string `json:"SubnetId"`
	PublicIPAddress string `json:"PublicIpAddress"`
	SecurityGroups  []struct {
		GroupID string `json:"GroupId"`
	} `json:"SecurityGroups"`
	IamInstanceProfile *struct {
		Arn string `json:"Arn"`
	} `json:"IamInstanceProfile"`
	MetadataOptions struct {
		HTTPTokens string `json:"HttpTokens"`
	} `json:"MetadataOptions"`
	Tags []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"Tags"`
}

// Name returns the Name tag, or the instance ID when there is none.
func (i Instance) Name() string {
	for _, t := range i.Tags {
		if t.Key == "Name" && t.Value != "" {
			return t.Value
		}
	}
	return i.InstanceID
}

// SecurityGroup is one entry of ec2:DescribeSecurityGroups.
type SecurityGroup struct {
	GroupID       string `json:"GroupId"`
	IPPermissions []struct {
		IPProtocol string `json:"IpProtocol"`
		FromPort   *int   `json:"FromPort"`
		ToPort     *int   `json:"ToPort"`
		IPRanges   []struct {
			CidrIP string `json:"CidrIp"`
		} `json:"IpRanges"`
	} `json:"IpPermissions"`
}

// RouteTable is one entry of ec2:DescribeRouteTables.
type RouteTable struct {
	RouteTableID string `json:"RouteTableId"`
	VpcID        string `json:"VpcId"`
	Associations []struct {
		Main     bool   `json:"Main"`
		SubnetID string `json:"SubnetId"`
	} `json:"Associations"`
	Routes []struct {
		DestinationCidrBlock string `json:"DestinationCidrBlock"`
		GatewayID            string `json:"GatewayId"`
		NatGatewayID         string `json:"NatGatewayId"`
		TransitGatewayID     string `json:"TransitGatewayId"`
		VpcPeeringID         string `json:"VpcPeeringConnectionId"`
		NetworkInterfaceID   string `json:"NetworkInterfaceId"`
	} `json:"Routes"`
}

// NetworkACL is one entry of ec2:DescribeNetworkAcls.
type NetworkACL struct {
	NetworkACLID string `json:"NetworkAclId"`
	Associations []struct {
		SubnetID string `json:"SubnetId"`
	} `json:"Associations"`
	Entries []NetworkACLEntry `json:"Entries"`
}

// NetworkACLEntry is one numbered rule of a network ACL.
type NetworkACLEntry struct {
	RuleNumber int    `json:"RuleNumber"`
	Protocol   string `json:"Protocol"` // "6" is TCP, "-1" is all
	RuleAction string `json:"RuleAction"`
	Egress     bool   `json:"Egress"`
	CidrBlock  string `json:"CidrBlock"`
	PortRange  *struct {
		From int `json:"From"`
		To   int `json:"To"`
	} `json:"PortRange"`
}

// RoleDetail is one entry of RoleDetailList in iam:GetAccountAuthorizationDetails.
type RoleDetail struct {
	RoleName            string `json:"RoleName"`
	InstanceProfileList []struct {
		Arn string `json:"Arn"`
	} `json:"InstanceProfileList"`
	RolePolicyList []struct {
		PolicyName     string         `json:"PolicyName"`
		PolicyDocument PolicyDocument `json:"PolicyDocument"`
	} `json:"RolePolicyList"`
	AttachedManagedPolicies []struct {
		PolicyName string `json:"PolicyName"`
		PolicyArn  string `json:"PolicyArn"`
	} `json:"AttachedManagedPolicies"`
	PermissionsBoundary *struct {
		PermissionsBoundaryArn string `json:"PermissionsBoundaryArn"`
	} `json:"PermissionsBoundary"`
}

// ManagedPolicy is one entry of Policies in iam:GetAccountAuthorizationDetails.
type ManagedPolicy struct {
	Arn               string `json:"Arn"`
	PolicyVersionList []struct {
		IsDefaultVersion bool           `json:"IsDefaultVersion"`
		Document         PolicyDocument `json:"Document"`
	} `json:"PolicyVersionList"`
}

// PolicyDocument is an IAM policy document in its decoded JSON form.
type PolicyDocument struct {
	Statement Statements `json:"Statement"`
}

// Statements decodes a Statement field, which IAM allows to be one object or a list.
type Statements []Statement

// UnmarshalJSON accepts both {...} and [{...}, ...].
func (s *Statements) UnmarshalJSON(b []byte) error {
	var one Statement
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = Statements{one}
		return nil
	}
	var many []Statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Statement is one IAM policy statement.
type Statement struct {
	Effect   string     `json:"Effect"`
	Action   StringList `json:"Action"`
	Resource StringList `json:"Resource"`
}

// StringList decodes an IAM field that may be one string or a list of strings.
type StringList []string

// UnmarshalJSON accepts both "x" and ["x", "y"].
func (s *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}
