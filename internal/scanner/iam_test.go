package scanner

import (
	"context"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeIAM implements iamAPI against an in-memory set of roles and policy
// documents, keyed by role name, so discoverIAM can be tested without
// hitting AWS.
type fakeIAM struct {
	roles            []types.Role
	inlinePolicies   map[string]map[string]string // role -> policy name -> raw JSON doc
	attachedPolicies map[string][]types.AttachedPolicy
	policyDocuments  map[string]string // policy ARN -> raw JSON doc
}

func (f *fakeIAM) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func (f *fakeIAM) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attachedPolicies[aws.ToString(params.RoleName)]}, nil
}

func (f *fakeIAM) ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	var names []string
	for name := range f.inlinePolicies[aws.ToString(params.RoleName)] {
		names = append(names, name)
	}
	return &iam.ListRolePoliciesOutput{PolicyNames: names}, nil
}

func (f *fakeIAM) GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	doc := f.inlinePolicies[aws.ToString(params.RoleName)][aws.ToString(params.PolicyName)]
	return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(url.QueryEscape(doc))}, nil
}

func (f *fakeIAM) GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &types.Policy{
		Arn:              params.PolicyArn,
		DefaultVersionId: aws.String("v1"),
	}}, nil
}

func (f *fakeIAM) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	doc := f.policyDocuments[aws.ToString(params.PolicyArn)]
	return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{
		VersionId: params.VersionId,
		Document:  aws.String(url.QueryEscape(doc)),
	}}, nil
}

func TestDiscoverIAM_WildcardActionViaInlinePolicy(t *testing.T) {
	fake := &fakeIAM{
		roles: []types.Role{
			{RoleName: aws.String("deploy-role"), Arn: aws.String("arn:aws:iam::123456789012:role/deploy-role")},
		},
		inlinePolicies: map[string]map[string]string{
			"deploy-role": {
				"AllowEverything": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			},
		},
	}

	resources, err := discoverIAM(context.Background(), fake)
	if err != nil {
		t.Fatalf("discoverIAM() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(resources))
	}

	r := resources[0]
	if got := r.Metadata["has_wildcard_action"]; got != true {
		t.Errorf("has_wildcard_action = %v, want true", got)
	}
	if got := r.Metadata["has_wildcard_resource"]; got != true {
		t.Errorf("has_wildcard_resource = %v, want true", got)
	}
}

func TestDiscoverIAM_WildcardActionViaAttachedPolicy(t *testing.T) {
	arn := "arn:aws:iam::123456789012:policy/AdminAccess"
	fake := &fakeIAM{
		roles: []types.Role{
			{RoleName: aws.String("admin-role"), Arn: aws.String("arn:aws:iam::123456789012:role/admin-role")},
		},
		attachedPolicies: map[string][]types.AttachedPolicy{
			"admin-role": {{PolicyArn: aws.String(arn), PolicyName: aws.String("AdminAccess")}},
		},
		policyDocuments: map[string]string{
			arn: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		},
	}

	resources, err := discoverIAM(context.Background(), fake)
	if err != nil {
		t.Fatalf("discoverIAM() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(resources))
	}
	if got := resources[0].Metadata["has_wildcard_action"]; got != true {
		t.Errorf("has_wildcard_action = %v, want true", got)
	}
}

func TestDiscoverIAM_ScopedPolicyNoFinding(t *testing.T) {
	fake := &fakeIAM{
		roles: []types.Role{
			{RoleName: aws.String("read-only-role"), Arn: aws.String("arn:aws:iam::123456789012:role/read-only-role")},
		},
		inlinePolicies: map[string]map[string]string{
			"read-only-role": {
				"ReadOnly": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::my-bucket/*"}]}`,
			},
		},
	}

	resources, err := discoverIAM(context.Background(), fake)
	if err != nil {
		t.Fatalf("discoverIAM() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(resources))
	}

	r := resources[0]
	if got := r.Metadata["has_wildcard_action"]; got != false {
		t.Errorf("has_wildcard_action = %v, want false", got)
	}
	if got := r.Metadata["has_wildcard_resource"]; got != false {
		t.Errorf("has_wildcard_resource = %v, want false", got)
	}
}
