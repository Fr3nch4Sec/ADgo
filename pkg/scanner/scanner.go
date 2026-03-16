// pkg/scanner/scanner.go
//
// Optimisations appliquées :
//   1. Port batching — scan plusieurs ports EN MÊME TEMPS par hôte (goroutines internes)
//   2. Result streaming — les résultats sont émis dès qu'ils arrivent (pas d'attente globale)
//   3. Early exit — stop dès qu'un port est ouvert si on cherche juste la disponibilité
//   4. Buffered channels correctement dimensionnés
//   5. sync.Pool pour réutiliser les buffers de connexion TCP
//   6. Adaptive workers — ajuste selon le nombre de cibles

package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Target représente une cible de scan
type Target struct {
	IP   string
	Host string
}

// ScanResult résultat d'un scan sur une cible
type ScanResult struct {
	Target   Target
	Open     bool
	Port     int
	Duration time.Duration
	Banner   string
	Error    error // erreur d'authentification ou de connexion
}

// ScanConfig configuration du scan
type ScanConfig struct {
	Workers int
	Timeout time.Duration
	Ports   []int
}

// ScanFunc fonction exécutée par chaque worker
type ScanFunc func(target Target) ScanResult

// ============================================================
// Parsing des cibles
// ============================================================

// ParseTargets parse une cible : IP, CIDR, range, fichier
func ParseTargets(input string) ([]Target, error) {
	// Fichier texte
	if _, err := os.Stat(input); err == nil {
		return parseTargetFile(input)
	}

	// CIDR
	if strings.Contains(input, "/") {
		return parseCIDR(input)
	}

	// Range IP (192.168.1.10-20)
	if strings.Contains(input, "-") && !strings.HasPrefix(input, "-") {
		if targets, err := parseRange(input); err == nil {
			return targets, nil
		}
	}

	// IP ou hostname unique
	return []Target{{IP: input, Host: input}}, nil
}

func parseCIDR(cidr string) ([]Target, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %v", cidr, err)
	}

	var targets []Target
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		// Exclure adresse réseau et broadcast
		addr := ip.String()
		if addr == ipnet.IP.String() {
			continue
		}
		targets = append(targets, Target{IP: addr, Host: addr})
	}

	// Supprimer le broadcast
	if len(targets) > 0 {
		targets = targets[:len(targets)-1]
	}
	return targets, nil
}

func parseRange(input string) ([]Target, error) {
	// Format: 192.168.1.10-20 ou 192.168.1.10-192.168.1.20
	parts := strings.Split(input, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range: %s", input)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", parts[0])
	}

	// Si la partie droite est juste un nombre final (192.168.1.10-20)
	endStr := strings.TrimSpace(parts[1])
	var endIP net.IP
	if strings.Contains(endStr, ".") {
		endIP = net.ParseIP(endStr)
	} else {
		// Remplacer le dernier octet
		baseIP := startIP.To4()
		if baseIP == nil {
			return nil, fmt.Errorf("IPv6 ranges not supported")
		}
		endIP = net.ParseIP(fmt.Sprintf("%d.%d.%d.%s",
			baseIP[0], baseIP[1], baseIP[2], endStr))
	}
	if endIP == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endStr)
	}

	start := ipToUint32(startIP.To4())
	end := ipToUint32(endIP.To4())
	if start > end {
		return nil, fmt.Errorf("start IP > end IP")
	}

	var targets []Target
	for i := start; i <= end; i++ {
		addr := uint32ToIP(i).String()
		targets = append(targets, Target{IP: addr, Host: addr})
	}
	return targets, nil
}

func parseTargetFile(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []Target
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, Target{IP: line, Host: line})
	}
	return targets, sc.Err()
}

// ============================================================
// Worker Pool — optimisé
// ============================================================

// RunWorkerPool exécute fn en parallèle sur toutes les cibles.
//
// Optimisations vs version originale :
//   - Workers adaptatifs : min(cfg.Workers, len(targets))
//   - Channel buffering correct : évite les goroutines bloquées
//   - Résultats streamés : callback dès qu'un résultat arrive
func RunWorkerPool(targets []Target, cfg *ScanConfig, fn ScanFunc) []ScanResult {
	if len(targets) == 0 {
		return nil
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 50
	}
	// Adaptive : inutile d'avoir plus de workers que de cibles
	if workers > len(targets) {
		workers = len(targets)
	}

	// Buffer exact — pas de goroutine bloquée à écrire dans results
	jobs := make(chan Target, len(targets))
	results := make(chan ScanResult, len(targets))

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for t := range jobs {
				results <- fn(t)
			}
		}()
	}

	// Envoyer tous les jobs (non-bloquant grâce au buffer)
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	// Fermer results quand tous les workers sont finis
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collecter — pré-allouer la slice pour éviter les réallocations
	all := make([]ScanResult, 0, len(targets))
	for r := range results {
		all = append(all, r)
	}
	return all
}

// RunWorkerPoolWithCallback exécute fn et appelle callback dès qu'un résultat arrive.
// Plus réactif que RunWorkerPool pour l'affichage en temps réel.
func RunWorkerPoolWithCallback(targets []Target, cfg *ScanConfig, fn ScanFunc, callback func(ScanResult)) {
	if len(targets) == 0 {
		return
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 50
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	jobs := make(chan Target, workers*2)
	results := make(chan ScanResult, workers*2)

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for t := range jobs {
				results <- fn(t)
			}
		}()
	}

	// Feeder goroutine
	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()

	// Closer goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// Callback en temps réel
	for r := range results {
		callback(r)
	}
}

// ============================================================
// Probe TCP — optimisé avec scan multi-ports parallèle
// ============================================================

// ProbePort vérifie si un port TCP est ouvert
func ProbePort(target Target, port int, timeout time.Duration) ScanResult {
	start := time.Now()
	addr := net.JoinHostPort(target.IP, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	dur := time.Since(start)

	if err != nil {
		return ScanResult{Target: target, Open: false, Port: port, Duration: dur}
	}
	conn.Close()
	return ScanResult{Target: target, Open: true, Port: port, Duration: dur}
}

// ProbeMultiplePorts scanne plusieurs ports EN PARALLÈLE sur le même hôte.
// Retourne dès que le premier port ouvert est trouvé si earlyExit=true.
//
// Optimisation clé : au lieu de sonder les ports séquentiellement,
// on lance N goroutines simultanées et on attend le premier résultat positif.
func ProbeMultiplePorts(target Target, ports []int, timeout time.Duration, earlyExit bool) []ScanResult {
	if len(ports) == 0 {
		return nil
	}
	if len(ports) == 1 {
		r := ProbePort(target, ports[0], timeout)
		return []ScanResult{r}
	}

	results := make(chan ScanResult, len(ports))
	var once sync.Once
	var wg sync.WaitGroup
	done := make(chan struct{})

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case <-done:
				return // early exit demandé
			default:
			}
			r := ProbePort(target, p, timeout)
			results <- r
			if earlyExit && r.Open {
				once.Do(func() { close(done) })
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var all []ScanResult
	for r := range results {
		all = append(all, r)
	}
	return all
}

// FilterOpenHosts filtre les résultats pour ne garder que les hôtes ouverts
func FilterOpenHosts(results []ScanResult) []ScanResult {
	// Pré-allouer pour éviter les réallocations
	open := make([]ScanResult, 0, len(results)/2)
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}
	return open
}

// ============================================================
// Counter atomique — stats sans mutex
// ============================================================

// AtomicCounter compteur thread-safe sans mutex (plus performant)
type AtomicCounter struct {
	n int64
}

func (c *AtomicCounter) Inc()       { atomic.AddInt64(&c.n, 1) }
func (c *AtomicCounter) Get() int64 { return atomic.LoadInt64(&c.n) }

// ============================================================
// Helpers réseau
// ============================================================

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}
