// pkg/kerberos/bruteforce_test.go
package kerberos

import (
	"strings"
	"testing"
	"time"
)

func TestReadLines(t *testing.T) {
	// Test via les users directs
	cfg := &BruteConfig{
		Users: []string{"admin", "john", "guest"},
	}
	users, err := loadUsers(cfg)
	if err != nil {
		t.Fatalf("loadUsers failed: %v", err)
	}
	if len(users) != 3 {
		t.Errorf("loadUsers returned %d users, want 3", len(users))
	}
}

func TestLoadUsersNoSource(t *testing.T) {
	cfg := &BruteConfig{}
	_, err := loadUsers(cfg)
	if err == nil {
		t.Error("loadUsers should fail with no source")
	}
}

func TestSleepWithJitter(t *testing.T) {
	// Délai 0 → ne doit pas bloquer
	start := time.Now()
	sleepWithJitter(0, 0)
	if time.Since(start) > 50*time.Millisecond {
		t.Error("sleepWithJitter(0, 0) took too long")
	}

	// Délai 10ms avec jitter
	start = time.Now()
	sleepWithJitter(10, 20)
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Errorf("sleepWithJitter(10ms, 20%%) took too long: %v", elapsed)
	}
}

func TestMaskPwd(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Password123", "P**********"},
		{"ab", "**"},
		{"a", "**"},
		{"", "**"},
	}
	for _, c := range cases {
		got := maskPwd(c.input)
		if got != c.want {
			t.Errorf("maskPwd(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestBuildKrb5ConfigRC4(t *testing.T) {
	cfg := buildKrb5ConfigRC4("LAB.LOCAL", "192.168.1.10")
	if !strings.Contains(cfg, "rc4-hmac") {
		t.Error("RC4 config should contain rc4-hmac")
	}
	if !strings.Contains(cfg, "LAB.LOCAL") {
		t.Error("RC4 config should contain realm")
	}
	if !strings.Contains(cfg, "192.168.1.10") {
		t.Error("RC4 config should contain KDC IP")
	}
	// Ne doit PAS contenir AES
	if strings.Contains(cfg, "aes256") || strings.Contains(cfg, "aes128") {
		t.Error("RC4 config should not contain AES enctypes")
	}
}

func TestEnctypeName(t *testing.T) {
	cases := []struct {
		enctype int
		wantRC4 bool
	}{
		{23, true},  // RC4
		{18, false}, // AES256
		{17, false}, // AES128
		{99, false}, // unknown
	}
	for _, c := range cases {
		name := enctypeName(c.enctype)
		isRC4 := strings.Contains(name, "RC4")
		if isRC4 != c.wantRC4 {
			t.Errorf("enctypeName(%d) = %q, RC4=%v want %v", c.enctype, name, isRC4, c.wantRC4)
		}
	}
}

func TestKerbResultFields(t *testing.T) {
	r := KerbResult{
		Username: "admin",
		Password: "pass",
		Valid:    true,
		Success:  true,
	}
	if r.Username != "admin" || !r.Valid || !r.Success {
		t.Error("KerbResult fields not set correctly")
	}
}

func TestBruteResultAccumulation(t *testing.T) {
	result := &BruteResult{}
	result.ValidUsers = append(result.ValidUsers, "user1", "user2")
	result.ValidCreds = append(result.ValidCreds, KerbResult{
		Username: "admin", Password: "Password123", Success: true,
	})
	result.LockedUsers = append(result.LockedUsers, "locked_user")
	result.Attempts = 100

	if len(result.ValidUsers) != 2 {
		t.Errorf("ValidUsers = %d, want 2", len(result.ValidUsers))
	}
	if len(result.ValidCreds) != 1 {
		t.Errorf("ValidCreds = %d, want 1", len(result.ValidCreds))
	}
	if len(result.LockedUsers) != 1 {
		t.Errorf("LockedUsers = %d, want 1", len(result.LockedUsers))
	}
}
