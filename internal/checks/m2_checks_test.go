package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

func TestSimFindingVerdictMapping(t *testing.T) {
	tests := []struct {
		name      string
		outcome   *collect.SimOutcome
		failLevel Level
		wantLevel Level
	}{
		{"allowed", &collect.SimOutcome{}, LevelError, LevelOK},
		{"hard deny at declared level", &collect.SimOutcome{DeniedActions: []string{"a:b"}}, LevelError, LevelError},
		{"hard deny at warn level", &collect.SimOutcome{DeniedActions: []string{"a:b"}}, LevelWarn, LevelWarn},
		{"condition-dependent demotes to unknown", &collect.SimOutcome{ConditionActions: []string{"a:b"}, MissingContext: []string{"aws:SourceIp"}}, LevelError, LevelUnknown},
		{"simulation failure is unknown", &collect.SimOutcome{Err: errors.New("AccessDenied")}, LevelError, LevelUnknown},
		{"nil outcome is unknown", nil, LevelError, LevelUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := simFinding("IAM-001", "role/r", "role r", tt.outcome, tt.failLevel, "the actions", "fix it")
			if f.Level != tt.wantLevel {
				t.Errorf("level = %s, want %s", f.Level, tt.wantLevel)
			}
		})
	}
}

func TestIamRoleChecksSkipWithoutRole(t *testing.T) {
	s := collect.NewSnapshot()
	s.TaskRole.Complete(&collect.IAMRoleInfo{Source: collect.RoleSourceNone}, nil)
	s.ExecLogConfig.Complete(&collect.LogConfigInfo{KMSKeyID: "key-1"}, nil)

	for _, c := range []Check{NewIam001(), NewIam004()} {
		findings := c.Run(context.Background(), s)
		if len(findings) != 1 || findings[0].Level != LevelSkip {
			t.Errorf("%s: findings = %+v, want single skip", c.ID(), findings)
		}
	}
}

func TestIam007InvertedPolarity(t *testing.T) {
	run := func(outcome *collect.SimOutcome) Finding {
		s := collect.NewSnapshot()
		s.CallerIdentity.Complete(&collect.CallerInfo{
			Arn:             "arn:aws:iam::123456789012:user/tori",
			SSMStartSession: outcome,
		}, nil)
		findings := NewIam007().Run(context.Background(), s)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		return findings[0]
	}

	if f := run(&collect.SimOutcome{}); f.Level != LevelWarn {
		t.Errorf("allowed StartSession: level = %s, want warn (inverted)", f.Level)
	}
	if f := run(&collect.SimOutcome{DeniedActions: []string{"ssm:StartSession"}}); f.Level != LevelOK {
		t.Errorf("denied StartSession: level = %s, want ok (inverted)", f.Level)
	}
	if f := run(&collect.SimOutcome{ConditionActions: []string{"ssm:StartSession"}}); f.Level != LevelUnknown {
		t.Errorf("condition-dependent StartSession: level = %s, want unknown", f.Level)
	}
}

func TestNet002DecisionTable(t *testing.T) {
	const ssmEndpoint = "com.amazonaws.ap-northeast-1.ssmmessages"
	tests := []struct {
		name    string
		network *collect.NetworkInfo
		want    Level
	}{
		{"public route", &collect.NetworkInfo{Awsvpc: true, HasPublicRoute: aws.Bool(true)}, LevelOK},
		{"no route with endpoint", &collect.NetworkInfo{Awsvpc: true, HasPublicRoute: aws.Bool(false), VPCEndpoints: []string{ssmEndpoint}}, LevelOK},
		{"no route no endpoint", &collect.NetworkInfo{Awsvpc: true, HasPublicRoute: aws.Bool(false)}, LevelError},
		{"indirect route no endpoint", &collect.NetworkInfo{Awsvpc: true, RouteNote: "default route via transit gateway (reachability not verifiable)"}, LevelWarn},
		{"indirect route with endpoint", &collect.NetworkInfo{Awsvpc: true, RouteNote: "default route via transit gateway (reachability not verifiable)", VPCEndpoints: []string{ssmEndpoint}}, LevelOK},
		{"route query failed", &collect.NetworkInfo{Awsvpc: true, RouteErr: errors.New("UnauthorizedOperation")}, LevelUnknown},
		{"subnet query failed", &collect.NetworkInfo{Awsvpc: true, SubnetErr: errors.New("shared subnet")}, LevelUnknown},
		{"no route, endpoint list failed", &collect.NetworkInfo{Awsvpc: true, HasPublicRoute: aws.Bool(false), EndpointErr: errors.New("UnauthorizedOperation")}, LevelUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := collect.NewSnapshot()
			s.Task.Complete(&ecstypes.Task{TaskArn: aws.String(taskArn)}, nil)
			s.Network.Complete(tt.network, nil)
			findings := NewNet002().Run(context.Background(), s)
			if len(findings) != 1 || findings[0].Level != tt.want {
				t.Errorf("findings = %+v, want single %s", findings, tt.want)
			}
		})
	}
}

func TestTask004PlatformVersion(t *testing.T) {
	run := func(pv, family string) Level {
		s := collect.NewSnapshot()
		s.Task.Complete(&ecstypes.Task{
			TaskArn:         aws.String(taskArn),
			LaunchType:      ecstypes.LaunchTypeFargate,
			PlatformVersion: aws.String(pv),
			PlatformFamily:  aws.String(family),
		}, nil)
		findings := NewTask004().Run(context.Background(), s)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		return findings[0].Level
	}

	if got := run("1.4.0", "Linux"); got != LevelOK {
		t.Errorf("Linux 1.4.0 = %s, want ok", got)
	}
	if got := run("1.3.0", "Linux"); got != LevelError {
		t.Errorf("Linux 1.3.0 = %s, want error", got)
	}
	if got := run("1.0.0", "Windows Server 2019 Core"); got != LevelOK {
		t.Errorf("Windows 1.0.0 = %s, want ok", got)
	}
	if got := run("LATEST", "Linux"); got != LevelUnknown {
		t.Errorf("unparsable PV = %s, want unknown", got)
	}
}

func TestTask005AgentVersion(t *testing.T) {
	run := func(agentVersion string, windows bool) Level {
		s := collect.NewSnapshot()
		s.Task.Complete(&ecstypes.Task{TaskArn: aws.String(taskArn), LaunchType: ecstypes.LaunchTypeEc2}, nil)
		ci := &ecstypes.ContainerInstance{
			Ec2InstanceId: aws.String("i-1"),
			VersionInfo:   &ecstypes.VersionInfo{AgentVersion: aws.String(agentVersion)},
		}
		if windows {
			ci.Attributes = []ecstypes.Attribute{{Name: aws.String("ecs.os-type"), Value: aws.String("windows")}}
		}
		s.ContainerInstance.Complete(ci, nil)
		findings := NewTask005().Run(context.Background(), s)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		return findings[0].Level
	}

	if got := run("1.50.2", false); got != LevelOK {
		t.Errorf("Linux agent 1.50.2 = %s, want ok", got)
	}
	if got := run("1.50.1", false); got != LevelError {
		t.Errorf("Linux agent 1.50.1 = %s, want error", got)
	}
	if got := run("1.55.0", true); got != LevelError {
		t.Errorf("Windows agent 1.55.0 = %s, want error", got)
	}
	if got := run("1.56.0", true); got != LevelOK {
		t.Errorf("Windows agent 1.56.0 = %s, want ok", got)
	}
}

func TestTdef006NoProxyCoverage(t *testing.T) {
	taskDef := func(env ...ecstypes.KeyValuePair) *ecstypes.TaskDefinition {
		return &ecstypes.TaskDefinition{
			ContainerDefinitions: []ecstypes.ContainerDefinition{{
				Name:        aws.String("app"),
				Environment: env,
			}},
		}
	}
	kv := func(name, value string) ecstypes.KeyValuePair {
		return ecstypes.KeyValuePair{Name: aws.String(name), Value: aws.String(value)}
	}

	s := collect.NewSnapshot()
	s.TaskDefinition.Complete(taskDef(
		kv("HTTPS_PROXY", "http://proxy:3128"),
		kv("NO_PROXY", "169.254.169.254,169.254.170.2"),
	), nil)
	findings := NewTdef006().Run(context.Background(), s)
	if len(findings) != 1 || findings[0].Level != LevelOK {
		t.Errorf("complete NO_PROXY: findings = %+v, want ok", findings)
	}

	s = collect.NewSnapshot()
	s.TaskDefinition.Complete(taskDef(
		kv("HTTPS_PROXY", "http://proxy:3128"),
		kv("NO_PROXY", "169.254.169.254"),
	), nil)
	findings = NewTdef006().Run(context.Background(), s)
	if len(findings) != 1 || findings[0].Level != LevelWarn {
		t.Errorf("incomplete NO_PROXY: findings = %+v, want warn", findings)
	}
}

func TestCluster001(t *testing.T) {
	run := func(info *collect.ClusterInfo) Finding {
		s := collect.NewSnapshot()
		s.Cluster.Complete(info, nil)
		findings := NewCluster001().Run(context.Background(), s)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		return findings[0]
	}

	if f := run(&collect.ClusterInfo{Name: "c"}); f.Level != LevelError {
		t.Errorf("missing cluster: level = %s, want error", f.Level)
	}
	if f := run(&collect.ClusterInfo{Name: "c", Cluster: &ecstypes.Cluster{Status: aws.String("INACTIVE")}}); f.Level != LevelError {
		t.Errorf("inactive cluster: level = %s, want error", f.Level)
	}
	if f := run(&collect.ClusterInfo{Name: "c", Cluster: &ecstypes.Cluster{Status: aws.String("ACTIVE")}}); f.Level != LevelOK {
		t.Errorf("active cluster: level = %s, want ok", f.Level)
	}
}

func TestCluster003KMSStates(t *testing.T) {
	run := func(cfg *collect.LogConfigInfo) Level {
		s := collect.NewSnapshot()
		s.ExecLogConfig.Complete(cfg, nil)
		findings := NewCluster003().Run(context.Background(), s)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		return findings[0].Level
	}

	if got := run(&collect.LogConfigInfo{KMSKeyID: "k", KMSKeyMissing: true}); got != LevelError {
		t.Errorf("missing key = %s, want error", got)
	}
	if got := run(&collect.LogConfigInfo{KMSKeyID: "k", KMSKeyErr: errors.New("AccessDenied")}); got != LevelUnknown {
		t.Errorf("denied DescribeKey = %s, want unknown", got)
	}
}
