// pkg/spray/ratelimit_test.go
package spray

import (
	"testing"
	"time"
)

func TestNewRateLimiterSafe(t *testing.T) {
	policy := &LockoutPolicy{
		Threshold:         5,
		ObservationWindow: 30 * time.Minute,
	}
	rl := NewRateLimiter(&RateLimiterConfig{
		Mode:      ModeSafe,
		Policy:    policy,
		JitterPct: 10,
	})
	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	if rl.currentDelay <= 0 {
		t.Errorf("delay should be positive, got %v", rl.currentDelay)
	}
	// Avec threshold=5, window=30min → max ~6 tentatives/30min → délai ~5min
	if rl.currentDelay > 10*time.Minute {
		t.Errorf("safe delay too long: %v (expected ≤10min for threshold=5, window=30min)", rl.currentDelay)
	}
}

func TestNewRateLimiterDefault(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{
		Mode:      ModeSafe,
		JitterPct: 0,
	})
	// Sans policy, devrait utiliser le défaut conservatif
	if rl.currentDelay < 1*time.Second {
		t.Errorf("default delay too short: %v", rl.currentDelay)
	}
}

func TestCalculateSafeDelay(t *testing.T) {
	cases := []struct {
		threshold int
		window    time.Duration
		maxDelay  time.Duration
	}{
		{5, 30 * time.Minute, 10 * time.Minute},
		{3, 10 * time.Minute, 7 * time.Minute},
		{10, 60 * time.Minute, 10 * time.Minute},
		{1, 30 * time.Minute, 31 * time.Second}, // threshold=1 → défaut
	}
	for _, c := range cases {
		delay := calculateSafeDelay(&RateLimiterConfig{
			Policy: &LockoutPolicy{
				Threshold:         c.threshold,
				ObservationWindow: c.window,
			},
		})
		if delay > c.maxDelay {
			t.Errorf("calculateSafeDelay(threshold=%d, window=%v) = %v, want ≤ %v",
				c.threshold, c.window, delay, c.maxDelay)
		}
		if delay < 1*time.Second {
			t.Errorf("calculateSafeDelay returned too-short delay: %v", delay)
		}
	}
}

func TestRateLimiterWait(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{
		Mode:          ModeSafe,
		CustomDelayMs: 10, // 10ms pour les tests
		JitterPct:     0,
	})

	start := time.Now()
	rl.Wait()
	elapsed := time.Since(start)

	if elapsed < 5*time.Millisecond {
		t.Errorf("Wait returned too fast: %v (expected ≥5ms)", elapsed)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Wait took too long: %v (expected <100ms for 10ms delay)", elapsed)
	}
}

func TestRateLimiterRecordLocked(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{
		Mode:          ModeAdaptive,
		CustomDelayMs: 100,
		JitterPct:     0,
	})
	rl.minDelay = 10 * time.Millisecond
	rl.maxDelay = 10 * time.Second

	initial := rl.currentDelay
	rl.RecordResult(false, 50*time.Millisecond, true) // compte locké

	if rl.currentDelay <= initial {
		t.Errorf("delay should increase after locked account (initial=%v, current=%v)",
			initial, rl.currentDelay)
	}
}

func TestRecommendDelay(t *testing.T) {
	// Doit juste ne pas paniquer
	RecommendDelay(nil)
	RecommendDelay(&LockoutPolicy{Threshold: 5, ObservationWindow: 30 * time.Minute})
	RecommendDelay(&LockoutPolicy{Threshold: 2, ObservationWindow: 10 * time.Minute})
}

func TestLockoutPolicyFromLDAP(t *testing.T) {
	// lockoutThreshold=5, lockoutObservationWindow=-18000000000 (30min en intervals 100ns)
	p := LockoutPolicyFromLDAP("5", "-18000000000")
	if p.Threshold != 5 {
		t.Errorf("threshold = %d, want 5", p.Threshold)
	}
	if p.ObservationWindow <= 0 {
		t.Errorf("observation window should be positive, got %v", p.ObservationWindow)
	}
}

func TestMinMaxDuration(t *testing.T) {
	a, b := 5*time.Second, 10*time.Second
	if minDuration(a, b) != a {
		t.Error("minDuration wrong")
	}
	if maxDuration(a, b) != b {
		t.Error("maxDuration wrong")
	}
}

func BenchmarkRateLimiterComputeDelay(b *testing.B) {
	rl := NewRateLimiter(&RateLimiterConfig{
		Mode:          ModeStealth,
		CustomDelayMs: 1000,
		JitterPct:     30,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.computeDelay()
	}
}
