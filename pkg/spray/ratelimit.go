// pkg/spray/ratelimit.go
//
// Rate limiting adaptatif avec détection comportementale.
//
// Problème : un spray trop rapide déclenche les SIEM (pics d'Event 4625).
// Solution : adapter dynamiquement le délai selon :
//   1. La politique de verrouillage du domaine (lockoutObservationWindow)
//   2. Les réponses du serveur (latence, codes d'erreur inhabituels)
//   3. Un profil de trafic aléatoire qui imite le comportement humain
//
// Modes de délai :
//   Safe     : respecte strictement la fenêtre d'observation (délai = window / (threshold-1))
//   Stealth  : ajoute du bruit gaussien + pauses longues aléatoires
//   Adaptive : ajuste en temps réel selon la latence observée

package spray

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

// RateLimitMode mode de rate limiting
type RateLimitMode int

const (
	ModeSafe     RateLimitMode = iota // respecte la fenêtre de lockout
	ModeStealth                       // bruyant mais indétectable
	ModeAdaptive                      // adaptatif selon les réponses
)

// RateLimiter contrôle le débit des tentatives d'authentification
type RateLimiter struct {
	mode         RateLimitMode
	baseDelay    time.Duration
	minDelay     time.Duration
	maxDelay     time.Duration
	jitterPct    float64
	currentDelay time.Duration
	attempts     int
	failures     int
	latencies    []time.Duration
	longPausePct float64 // probabilité d'une pause longue (simulation humaine)
	mu           sync.Mutex
}

// LockoutPolicy politique de verrouillage extraite de LDAP
type LockoutPolicy struct {
	Threshold         int           // nombre de mauvais mdp avant verrouillage
	ObservationWindow time.Duration // fenêtre de réinitialisation du compteur
	LockoutDuration   time.Duration // durée du verrouillage
}

// RateLimiterConfig configuration du rate limiter
type RateLimiterConfig struct {
	Mode          RateLimitMode
	Policy        *LockoutPolicy // si nil, utilise des valeurs par défaut sûres
	CustomDelayMs int            // délai de base si Mode == ModeSafe et pas de Policy
	JitterPct     int            // 0-50 : % de variation aléatoire
}

// NewRateLimiter crée un rate limiter adaptatif
func NewRateLimiter(cfg *RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		mode:         cfg.Mode,
		jitterPct:    float64(cfg.JitterPct) / 100.0,
		longPausePct: 0.02, // 2% de chances d'une pause longue (comportement humain)
	}

	switch cfg.Mode {
	case ModeSafe:
		rl.currentDelay = calculateSafeDelay(cfg)
		rl.minDelay = rl.currentDelay / 2
		rl.maxDelay = rl.currentDelay * 3

	case ModeStealth:
		// Délai de base plus long, beaucoup de jitter
		base := 30 * time.Second
		if cfg.Policy != nil && cfg.Policy.ObservationWindow > 0 {
			base = calculateSafeDelay(cfg) * 2
		}
		rl.currentDelay = base
		rl.minDelay = base / 2
		rl.maxDelay = base * 5
		rl.jitterPct = 0.4 // 40% de jitter en mode stealth
		rl.longPausePct = 0.05

	case ModeAdaptive:
		rl.currentDelay = 2 * time.Second // début conservatif
		rl.minDelay = 500 * time.Millisecond
		rl.maxDelay = 5 * time.Minute
	}

	rl.baseDelay = rl.currentDelay
	return rl
}

// calculateSafeDelay calcule le délai minimum pour rester sous le seuil de lockout
func calculateSafeDelay(cfg *RateLimiterConfig) time.Duration {
	if cfg.CustomDelayMs > 0 {
		return time.Duration(cfg.CustomDelayMs) * time.Millisecond
	}
	if cfg.Policy == nil || cfg.Policy.Threshold <= 1 {
		return 30 * time.Second // défaut conservatif
	}
	// Rester en dessous du seuil avec une marge de sécurité de 20%
	safeAttempts := float64(cfg.Policy.Threshold-1) * 0.8
	if safeAttempts < 1 {
		safeAttempts = 1
	}
	delay := time.Duration(float64(cfg.Policy.ObservationWindow) / safeAttempts)
	if delay < 1*time.Second {
		delay = 1 * time.Second
	}
	return delay
}

// Wait attend le délai calculé avant la prochaine tentative
func (rl *RateLimiter) Wait() {
	rl.mu.Lock()
	delay := rl.computeDelay()
	rl.attempts++
	rl.mu.Unlock()

	time.Sleep(delay)
}

// RecordResult enregistre le résultat d'une tentative pour l'adaptation
func (rl *RateLimiter) RecordResult(success bool, latency time.Duration, wasLocked bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if wasLocked {
		rl.failures++
	}

	// Garder les 20 dernières latences
	rl.latencies = append(rl.latencies, latency)
	if len(rl.latencies) > 20 {
		rl.latencies = rl.latencies[1:]
	}

	if rl.mode == ModeAdaptive {
		rl.adapt(wasLocked, latency)
	}
}

// adapt ajuste le délai en mode adaptatif
func (rl *RateLimiter) adapt(wasLocked bool, latency time.Duration) {
	if wasLocked {
		// Compte verrouillé → on a été trop rapides, doubler le délai
		rl.currentDelay = minDuration(rl.currentDelay*2, rl.maxDelay)
		fmt.Printf("\n[!] Account locked detected — increasing delay to %v\n", rl.currentDelay)
		return
	}

	// Analyser la latence moyenne
	if len(rl.latencies) >= 5 {
		avg := avgLatency(rl.latencies)
		// Si la latence augmente fortement → le serveur est stressé → ralentir
		if avg > 2*time.Second {
			rl.currentDelay = minDuration(
				time.Duration(float64(rl.currentDelay)*1.5),
				rl.maxDelay,
			)
		} else if avg < 200*time.Millisecond && rl.failures == 0 {
			// Latence faible et pas de lockout → on peut accélérer légèrement
			rl.currentDelay = maxDuration(
				time.Duration(float64(rl.currentDelay)*0.9),
				rl.minDelay,
			)
		}
	}
}

// computeDelay calcule le délai effectif avec jitter et pauses longues
func (rl *RateLimiter) computeDelay() time.Duration {
	delay := float64(rl.currentDelay)

	// Jitter gaussien (distribution normale tronquée)
	if rl.jitterPct > 0 {
		// Box-Muller transform pour distribution normale
		u1 := rand.Float64()
		u2 := rand.Float64()
		if u1 == 0 {
			u1 = 1e-10
		}
		z := math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2*math.Pi*u2)
		// Tronquer à ±2σ
		z = math.Max(-2, math.Min(2, z))
		delay += z * rl.jitterPct * delay
	}

	// Pause longue aléatoire (imitation comportement humain : pause café/distraction)
	if rand.Float64() < rl.longPausePct {
		pause := time.Duration(rand.Intn(300)+30) * time.Second // 30-330 secondes
		if rl.mode == ModeStealth {
			fmt.Printf("\n[*] Stealth pause: %v (simulating human behavior)\n", pause.Round(time.Second))
		}
		delay += float64(pause)
	}

	if delay < 0 {
		delay = float64(rl.minDelay)
	}

	return time.Duration(delay)
}

// PrintConfig affiche la configuration du rate limiter
func (rl *RateLimiter) PrintConfig() {
	modeStr := []string{"Safe", "Stealth", "Adaptive"}[rl.mode]
	fmt.Printf("[*] Rate limiting: %s | delay=%v | jitter=%.0f%%",
		modeStr, rl.currentDelay.Round(time.Millisecond), rl.jitterPct*100)
	if rl.longPausePct > 0 {
		fmt.Printf(" | long-pause=%.0f%%", rl.longPausePct*100)
	}
	fmt.Println()
}

// SafeDelay retourne le délai recommandé en clair pour l'affichage
func (rl *RateLimiter) SafeDelay() time.Duration {
	return rl.baseDelay
}

// ============================================================
// Helpers
// ============================================================

func avgLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	return sum / time.Duration(len(latencies))
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// LockoutPolicyFromLDAP construit une LockoutPolicy depuis les attributs LDAP récupérés
func LockoutPolicyFromLDAP(thresholdStr, observationWindowStr string) *LockoutPolicy {
	var threshold int
	fmt.Sscanf(thresholdStr, "%d", &threshold)
	if threshold == 0 {
		threshold = 10 // défaut conservatif
	}

	// observationWindow est en intervalles de 100ns (Windows FILETIME négatif)
	var raw int64
	fmt.Sscanf(observationWindowStr, "%d", &raw)
	if raw < 0 {
		raw = -raw
	}
	window := time.Duration(raw * 100) // ns
	if window == 0 {
		window = 30 * time.Minute // défaut conservatif
	}

	return &LockoutPolicy{
		Threshold:         threshold,
		ObservationWindow: window,
		LockoutDuration:   30 * time.Minute,
	}
}

// RecommendDelay affiche une recommandation de délai selon la politique
func RecommendDelay(policy *LockoutPolicy) {
	if policy == nil || policy.Threshold <= 0 {
		fmt.Println("[*] No lockout policy found — using default 30s delay")
		return
	}

	safe := calculateSafeDelay(&RateLimiterConfig{Policy: policy})
	fmt.Printf("[*] Lockout policy: threshold=%d | window=%v\n",
		policy.Threshold, policy.ObservationWindow.Round(time.Second))
	fmt.Printf("[*] Recommended delay: %v (%.1f attempts/hour max)\n",
		safe.Round(time.Second),
		float64(time.Hour)/float64(safe),
	)

	if policy.Threshold <= 3 {
		fmt.Printf("[!] LOW lockout threshold (%d) — very careful spray required!\n",
			policy.Threshold)
	}
}
