package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// iamAPI is the subset of *iam.Client that discoverIAM needs. Matching the
// concrete client's method signatures lets tests substitute a fake instead
// of hitting AWS.
type iamAPI interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

func discoverIAM(ctx context.Context, api iamAPI) ([]Resource, error) {
	var (
		resources []Resource
		errs      []error
	)

	paginator := iam.NewListRolesPaginator(api, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("listing roles: %w", err))
			break
		}

		for _, role := range page.Roles {
			name := aws.ToString(role.RoleName)

			hasAction, hasResource, actionPolicies, resourcePolicies, err := roleWildcardPermissions(ctx, api, name)
			if err != nil {
				errs = append(errs, fmt.Errorf("role %s: %w", name, err))
				continue
			}

			resources = append(resources, Resource{
				ID:     aws.ToString(role.Arn),
				Type:   "aws_iam_role",
				Region: "global",
				Metadata: map[string]any{
					"role_name":                  name,
					"has_wildcard_action":        hasAction,
					"has_wildcard_resource":      hasResource,
					"action_wildcard_policies":   actionPolicies,
					"resource_wildcard_policies": resourcePolicies,
				},
			})
		}
	}

	return resources, errors.Join(errs...)
}

// roleWildcardPermissions gathers every policy document attached to a role
// (inline and managed) and checks each Allow statement for "Action": "*" or
// "Resource": "*". A policy name is attributed to actionPolicies /
// resourcePolicies independently, so a policy that only wildcards one of
// the two never gets cited for the other.
func roleWildcardPermissions(ctx context.Context, api iamAPI, roleName string) (hasAction, hasResource bool, actionPolicies, resourcePolicies []string, err error) {
	docs, err := rolePolicyDocuments(ctx, api, roleName)
	if err != nil {
		return false, false, nil, nil, err
	}

	for policyName, doc := range docs {
		stmts, err := parsePolicyStatements(doc)
		if err != nil {
			return false, false, nil, nil, fmt.Errorf("parsing policy %s: %w", policyName, err)
		}

		actionMatched, resourceMatched := false, false
		for _, s := range stmts {
			if s.Effect != "Allow" {
				continue
			}
			if containsWildcard(s.Action) {
				hasAction = true
				actionMatched = true
			}
			if containsWildcard(s.Resource) {
				hasResource = true
				resourceMatched = true
			}
		}
		if actionMatched {
			actionPolicies = append(actionPolicies, policyName)
		}
		if resourceMatched {
			resourcePolicies = append(resourcePolicies, policyName)
		}
	}

	return hasAction, hasResource, actionPolicies, resourcePolicies, nil
}

// rolePolicyDocuments returns every policy document (inline + attached
// managed) reachable from a role, keyed by policy name.
func rolePolicyDocuments(ctx context.Context, api iamAPI, roleName string) (map[string]string, error) {
	docs := map[string]string{}

	inlinePaginator := iam.NewListRolePoliciesPaginator(api, &iam.ListRolePoliciesInput{RoleName: &roleName})
	for inlinePaginator.HasMorePages() {
		page, err := inlinePaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing inline policies: %w", err)
		}

		for _, policyName := range page.PolicyNames {
			out, err := api.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: &policyName})
			if err != nil {
				return nil, fmt.Errorf("getting inline policy %s: %w", policyName, err)
			}

			doc, err := decodePolicyDocument(aws.ToString(out.PolicyDocument))
			if err != nil {
				return nil, fmt.Errorf("decoding inline policy %s: %w", policyName, err)
			}
			docs[policyName] = doc
		}
	}

	attachedPaginator := iam.NewListAttachedRolePoliciesPaginator(api, &iam.ListAttachedRolePoliciesInput{RoleName: &roleName})
	for attachedPaginator.HasMorePages() {
		page, err := attachedPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing attached policies: %w", err)
		}

		for _, p := range page.AttachedPolicies {
			arn := aws.ToString(p.PolicyArn)
			policyName := aws.ToString(p.PolicyName)

			policyOut, err := api.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &arn})
			if err != nil {
				return nil, fmt.Errorf("getting policy %s: %w", policyName, err)
			}
			if policyOut.Policy == nil {
				continue
			}

			versionOut, err := api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: &arn,
				VersionId: policyOut.Policy.DefaultVersionId,
			})
			if err != nil {
				return nil, fmt.Errorf("getting policy version %s: %w", policyName, err)
			}
			if versionOut.PolicyVersion == nil {
				continue
			}

			doc, err := decodePolicyDocument(aws.ToString(versionOut.PolicyVersion.Document))
			if err != nil {
				return nil, fmt.Errorf("decoding policy %s: %w", policyName, err)
			}
			docs[policyName] = doc
		}
	}

	return docs, nil
}

// decodePolicyDocument un-does the URL encoding IAM applies to policy
// documents returned from Get* calls.
func decodePolicyDocument(raw string) (string, error) {
	return url.QueryUnescape(raw)
}

type iamStatement struct {
	Effect   string          `json:"Effect"`
	Action   json.RawMessage `json:"Action"`
	Resource json.RawMessage `json:"Resource"`
}

// parsePolicyStatements handles the fact that a policy document's Statement
// field is either a single object or an array of objects.
func parsePolicyStatements(doc string) ([]iamStatement, error) {
	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return nil, err
	}

	var stmts []iamStatement
	if err := json.Unmarshal(raw.Statement, &stmts); err == nil {
		return stmts, nil
	}

	var single iamStatement
	if err := json.Unmarshal(raw.Statement, &single); err != nil {
		return nil, err
	}
	return []iamStatement{single}, nil
}

// containsWildcard handles Action/Resource fields that are either a single
// string or an array of strings, per the IAM policy grammar.
func containsWildcard(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == "*"
	}

	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return slices.Contains(list, "*")
	}

	return false
}
