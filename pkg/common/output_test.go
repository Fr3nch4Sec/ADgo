// pkg/common/output_test.go
package common

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout capture la sortie standard pendant l'exécution de fn
func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = old
	return buf.String()
}

func TestPrintInfo(t *testing.T) {
	Quiet = false
	out := captureStdout(func() { PrintInfo("test message") })
	if !strings.Contains(out, "test message") {
		t.Errorf("PrintInfo output missing message: %q", out)
	}
}

func TestPrintInfoQuiet(t *testing.T) {
	Quiet = true
	defer func() { Quiet = false }()
	out := captureStdout(func() { PrintInfo("should not appear") })
	if strings.Contains(out, "should not appear") {
		t.Error("PrintInfo should be silent in quiet mode")
	}
}

func TestPrintSuccess(t *testing.T) {
	out := captureStdout(func() { PrintSuccess("operation ok") })
	if !strings.Contains(out, "operation ok") {
		t.Errorf("PrintSuccess missing message: %q", out)
	}
}

func TestPrintWarning(t *testing.T) {
	out := captureStdout(func() { PrintWarning("watch out") })
	if !strings.Contains(out, "watch out") {
		t.Errorf("PrintWarning missing message: %q", out)
	}
}

func TestPrintFound(t *testing.T) {
	out := captureStdout(func() { PrintFound("Computer", "DC01") })
	if !strings.Contains(out, "Computer") || !strings.Contains(out, "DC01") {
		t.Errorf("PrintFound missing label or value: %q", out)
	}
}

func TestPrintCredential(t *testing.T) {
	out := captureStdout(func() { PrintCredential("LAB", "administrator", "Password123") })
	if !strings.Contains(out, "administrator") {
		t.Errorf("PrintCredential missing username: %q", out)
	}
}

func TestPrintCount(t *testing.T) {
	out := captureStdout(func() { PrintCount(5, "users") })
	if !strings.Contains(out, "5") || !strings.Contains(out, "users") {
		t.Errorf("PrintCount missing count or label: %q", out)
	}
}

func TestPrintCountZero(t *testing.T) {
	out := captureStdout(func() { PrintCount(0, "computers") })
	if !strings.Contains(out, "No") || !strings.Contains(out, "computers") {
		t.Errorf("PrintCount zero should print 'No computers': %q", out)
	}
}

func TestPrintTable(t *testing.T) {
	headers := []string{"NAME", "VALUE", "STATUS"}
	rows := [][]string{
		{"DC01", "192.168.1.10", "ADMIN"},
		{"WEB01", "192.168.1.20", "YES"},
	}
	out := captureStdout(func() { PrintTable(headers, rows) })
	if !strings.Contains(out, "DC01") || !strings.Contains(out, "192.168.1.10") {
		t.Errorf("PrintTable missing data: %q", out)
	}
	if !strings.Contains(out, "NAME") {
		t.Errorf("PrintTable missing header: %q", out)
	}
}

func TestPrintTableEmpty(t *testing.T) {
	out := captureStdout(func() { PrintTable([]string{"A", "B"}, [][]string{}) })
	// Empty table should produce no output
	_ = out // no crash is the test
}

func TestSpinner(t *testing.T) {
	Quiet = false
	s := NewSpinner("Testing")
	s.Start()
	time.Sleep(200 * time.Millisecond)
	s.Stop()
	// Double stop should not panic
	s.Stop()
}

func TestSpinnerQuiet(t *testing.T) {
	Quiet = true
	defer func() { Quiet = false }()
	s := NewSpinner("Silent")
	s.Start()
	time.Sleep(50 * time.Millisecond)
	s.Stop() // should not crash
}

func TestIsHexString(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"aad3b435b51404eeaad3b435b51404ee", true},
		{"AABBCCDD11223344AABBCCDD11223344", true},
		{"not_hex_string!", false},
		{"", true}, // vacuously true
	}
	for _, c := range cases {
		got := isHexString(c.input)
		if got != c.want {
			t.Errorf("isHexString(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestNxSummaryLine(t *testing.T) {
	out := captureStdout(func() {
		NxSummaryLine("Hosts scanned", 42)
		NxSummaryLine("Duration", "3s")
	})
	if !strings.Contains(out, "Hosts scanned") || !strings.Contains(out, "42") {
		t.Errorf("NxSummaryLine missing content: %q", out)
	}
}

func TestPrintOutput_JSON(t *testing.T) {
	data := map[string]interface{}{"key": "value", "count": 3}
	out := captureStdout(func() { PrintOutput(data, false, true, false) })
	if !strings.Contains(out, "key") || !strings.Contains(out, "value") {
		t.Errorf("PrintOutput JSON missing content: %q", out)
	}
}

func TestPrintOutput_Strings(t *testing.T) {
	data := []string{"user1", "user2", "admin"}
	out := captureStdout(func() { PrintOutput(data, false, false, false) })
	if !strings.Contains(out, "user1") || !strings.Contains(out, "admin") {
		t.Errorf("PrintOutput strings missing content: %q", out)
	}
}

// Benchmark table rendering performance
func BenchmarkPrintTable(b *testing.B) {
	rows := make([][]string, 100)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("user%d", i), "192.168.1.1", "YES", "ADMIN"}
	}
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PrintTable([]string{"USER", "IP", "AUTH", "ADMIN"}, rows)
	}
}
