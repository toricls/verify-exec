package collect

import (
	"testing"
)

func TestRecordDecision(t *testing.T) {
	t.Run("all allowed", func(t *testing.T) {
		o := &SimOutcome{}
		recordDecision(o, "ecs:ExecuteCommand", "allowed", nil)
		if !o.Allowed() {
			t.Errorf("outcome = %+v, want allowed", o)
		}
	})
	t.Run("hard deny", func(t *testing.T) {
		o := &SimOutcome{}
		recordDecision(o, "ecs:ExecuteCommand", "implicitDeny", nil)
		if o.Allowed() || o.ConditionDependent() || len(o.DeniedActions) != 1 {
			t.Errorf("outcome = %+v, want hard deny", o)
		}
	})
	t.Run("condition-dependent deny", func(t *testing.T) {
		o := &SimOutcome{}
		recordDecision(o, "ecs:ExecuteCommand", "implicitDeny", []string{"aws:ResourceTag/env"})
		if !o.ConditionDependent() {
			t.Errorf("outcome = %+v, want condition-dependent", o)
		}
	})
	t.Run("hard deny wins over condition deny", func(t *testing.T) {
		o := &SimOutcome{}
		recordDecision(o, "a:b", "implicitDeny", []string{"aws:SourceIp"})
		recordDecision(o, "a:c", "explicitDeny", nil)
		if o.ConditionDependent() || len(o.DeniedActions) != 1 {
			t.Errorf("outcome = %+v, want hard deny to dominate", o)
		}
	})
}

func TestMergeOutcomes(t *testing.T) {
	a := &SimOutcome{DeniedActions: []string{"s3:PutObject"}}
	b := &SimOutcome{ConditionActions: []string{"s3:GetBucketLocation"}, MissingContext: []string{"aws:SourceVpc"}}
	m := mergeOutcomes(a, b)
	if len(m.DeniedActions) != 1 || len(m.ConditionActions) != 1 || len(m.MissingContext) != 1 {
		t.Errorf("merged = %+v", m)
	}
	if m.ConditionDependent() {
		t.Error("merged outcome with a hard deny must not be condition-dependent")
	}
}

func TestSimulatablePrincipal(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		wantArn  string
		wantKind principalKind
	}{
		{
			name:     "iam user",
			arn:      "arn:aws:iam::123456789012:user/tori",
			wantArn:  "arn:aws:iam::123456789012:user/tori",
			wantKind: principalSimulatable,
		},
		{
			name:     "assumed role",
			arn:      "arn:aws:sts::123456789012:assumed-role/admin-role/session-1",
			wantArn:  "arn:aws:iam::123456789012:role/admin-role",
			wantKind: principalSimulatable,
		},
		{
			name:     "root",
			arn:      "arn:aws:iam::123456789012:root",
			wantArn:  "",
			wantKind: principalRoot,
		},
		{
			name:     "federated user",
			arn:      "arn:aws:sts::123456789012:federated-user/bob",
			wantArn:  "",
			wantKind: principalUnsimulatable,
		},
		{
			name:     "garbage",
			arn:      "not-an-arn",
			wantArn:  "",
			wantKind: principalUnsimulatable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn, _, kind := simulatablePrincipal(tt.arn)
			if arn != tt.wantArn || kind != tt.wantKind {
				t.Errorf("simulatablePrincipal(%q) = (%q, %v), want (%q, %v)",
					tt.arn, arn, kind, tt.wantArn, tt.wantKind)
			}
		})
	}
}
