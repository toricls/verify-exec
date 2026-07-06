package checks

import (
	"context"
	"errors"
	"testing"
)

func TestLocal001(t *testing.T) {
	tests := []struct {
		name       string
		lookPath   func(string) (string, error)
		runVersion func(string) (string, error)
		wantLevel  Level
	}{
		{
			name:       "installed",
			lookPath:   func(string) (string, error) { return "/usr/local/bin/session-manager-plugin", nil },
			runVersion: func(string) (string, error) { return "1.2.553.0", nil },
			wantLevel:  LevelOK,
		},
		{
			name:      "not in PATH",
			lookPath:  func(string) (string, error) { return "", errors.New("not found") },
			wantLevel: LevelError,
		},
		{
			name:       "version command fails",
			lookPath:   func(string) (string, error) { return "/usr/local/bin/session-manager-plugin", nil },
			runVersion: func(string) (string, error) { return "", errors.New("exec format error") },
			wantLevel:  LevelError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &local001{lookPath: tt.lookPath, runVersion: tt.runVersion}
			findings := c.Run(context.Background(), nil)
			if len(findings) != 1 || findings[0].Level != tt.wantLevel {
				t.Errorf("findings = %+v, want single %s", findings, tt.wantLevel)
			}
		})
	}
}

func TestLocal002(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		err       error
		wantLevel Level
	}{
		{"v2 recent", "aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0 exe/x86_64", nil, LevelOK},
		{"v2 exactly minimum", "aws-cli/2.3.6 Python/3.8.8", nil, LevelOK},
		{"v2 too old", "aws-cli/2.3.5 Python/3.8.8", nil, LevelError},
		{"v1 recent", "aws-cli/1.32.0 Python/3.11.8", nil, LevelOK},
		{"v1 exactly minimum", "aws-cli/1.22.3 Python/3.6.0", nil, LevelOK},
		{"v1 too old", "aws-cli/1.19.28 Python/3.6.0", nil, LevelError},
		{"future major", "aws-cli/3.0.0", nil, LevelOK},
		{"not installed", "", errors.New("executable file not found in $PATH"), LevelError},
		{"unparsable", "something unexpected", nil, LevelUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &local002{awsVersion: func() (string, error) { return tt.output, tt.err }}
			findings := c.Run(context.Background(), nil)
			if len(findings) != 1 || findings[0].Level != tt.wantLevel {
				t.Errorf("findings = %+v, want single %s", findings, tt.wantLevel)
			}
		})
	}
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		v, min [3]int
		want   bool
	}{
		{[3]int{2, 3, 6}, [3]int{2, 3, 6}, true},
		{[3]int{2, 3, 7}, [3]int{2, 3, 6}, true},
		{[3]int{2, 4, 0}, [3]int{2, 3, 6}, true},
		{[3]int{2, 3, 5}, [3]int{2, 3, 6}, false},
		{[3]int{2, 2, 9}, [3]int{2, 3, 6}, false},
		{[3]int{1, 22, 3}, [3]int{1, 22, 3}, true},
		{[3]int{1, 21, 99}, [3]int{1, 22, 3}, false},
	}
	for _, tt := range tests {
		if got := versionAtLeast(tt.v, tt.min); got != tt.want {
			t.Errorf("versionAtLeast(%v, %v) = %v, want %v", tt.v, tt.min, got, tt.want)
		}
	}
}
