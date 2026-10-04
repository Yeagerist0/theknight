package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeSTS struct {
	account string
	err     error
}

func (f *fakeSTS) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account)}, nil
}

func TestCallerAccountID(t *testing.T) {
	id, err := callerAccountID(context.Background(), &fakeSTS{account: "123456789012"})
	if err != nil {
		t.Fatalf("callerAccountID() error = %v", err)
	}
	if id != "123456789012" {
		t.Errorf("callerAccountID() = %q, want %q", id, "123456789012")
	}
}

// TestCallerAccountID_ErrorIsNotFatal documents the contract Discover relies
// on: a failure here is a value the caller decides how to handle (degrade to
// "" and keep scanning), not something callerAccountID itself papers over.
func TestCallerAccountID_ErrorIsNotFatal(t *testing.T) {
	wantErr := errors.New("sts: access denied")
	_, err := callerAccountID(context.Background(), &fakeSTS{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Errorf("callerAccountID() error = %v, want %v", err, wantErr)
	}
}
