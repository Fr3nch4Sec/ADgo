// pkg/scanner/scanner.go
package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Target représente un hôte à scanner
type Target struct {
	IP   string
	Host string // hostname si fourni
}

// ScanResult résultat pour un hôte
type ScanResult struct {
	Target   Target
	Port     int
	Open     bool
	Banner   string // info SMB/WinRM basique
	Error    error
	Duration time.Duration
}

// ScanConfig configuration du scan
type ScanConfig struct {
	Ports   []int
	Timeout time.Duration
	Workers int
	Verbose bool
}

// DefaultScanConfig retourne une configuration par défaut
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Ports:   []int{445},
		Timeout: 2 * time.Second,
		Workers: 50,
	}
}

// ParseTargets parse une entrée qui peut être :
//   - une IP seule : "192.168.1.10"
//   - un CIDR : "192.168.1.0/24"
//   - une plage : "192.168.1.10-20"
//   - un hostname : "dc01.lab.local"
//   - un fichier : chemin vers un fichier texte (une cible par ligne)
func ParseTargets(input string) ([]Target, error) {
	// Essayer comme fichier en premier
	if _, err := os.Stat(input); err == nil {
		return parseTargetFile(input)
	}

	// CIDR (ex: 192.168.1.0/24)
	if strings.Contains(input, "/") {
		return parseCIDR(input)
	}

	// Plage (ex: 192.168.1.10-20)
	if strings.Contains(input, "-") {
		parts := strings.SplitN(input, "-", 2)
		// Vérifier si c'est une plage IP ou un hostname avec tiret
		if net.ParseIP(parts[0]) != nil {
			return parseIPRange(input)
		}
	}

	// IP unique ou hostname
	return []Target{{IP: input, Host: input}}, nil
}

func parseCIDR(cidr string) ([]Target, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %v", cidr, err)
	}

	var targets []Target
	for ip = ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		// Exclure adresse réseau et broadcast
		ipStr := ip.String()
		if isNetworkOrBroadcast(ip, ipNet) {
			continue
		}
		targets = append(targets, Target{IP: ipStr, Host: ipStr})
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no usable addresses in %s", cidr)
	}
	return targets, nil
}

func parseIPRange(rangeStr string) ([]Target, error) {
	// Format : "192.168.1.10-20" ou "192.168.1.10-192.168.1.20"
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range: %s", rangeStr)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", parts[0])
	}
	startIP = startIP.To4()

	endStr := strings.TrimSpace(parts[1])
	var endIP net.IP

	// Forme courte "192.168.1.10-20" → seul le dernier octet varie
	if !strings.Contains(endStr, ".") {
		lastOctet, err := strconv.Atoi(endStr)
		if err != nil || lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("invalid end octet: %s", endStr)
		}
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(lastOctet)
	} else {
		endIP = net.ParseIP(endStr).To4()
		if endIP == nil {
			return nil, fmt.Errorf("invalid end IP: %s", endStr)
		}
	}

	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)
	if start > end {
		return nil, fmt.Errorf("start IP is greater than end IP")
	}

	var targets []Target
	for i := start; i <= end; i++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, i)
		ipStr := net.IP(b).String()
		targets = append(targets, Target{IP: ipStr, Host: ipStr})
	}

	return targets, nil
}

func parseTargetFile(filename string) ([]Target, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open targets file: %v", err)
	}
	defer f.Close()

	var targets []Target
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Chaque ligne peut elle-même être un CIDR, range ou IP
		parsed, err := ParseTargets(line)
		if err != nil {
			// Avertir mais continuer
			fmt.Fprintf(os.Stderr, "[!] Skipping invalid target %q: %v\n", line, err)
			continue
		}
		targets = append(targets, parsed...)
	}

	return targets, scanner.Err()
}

// ProbePort vérifie si un port TCP est ouvert et retourne le résultat
func ProbePort(target Target, port int, timeout time.Duration) ScanResult {
	start := time.Now()
	addr := net.JoinHostPort(target.IP, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	dur := time.Since(start)

	if err != nil {
		return ScanResult{
			Target:   target,
			Port:     port,
			Open:     false,
			Error:    err,
			Duration: dur,
		}
	}
	conn.Close()

	return ScanResult{
		Target:   target,
		Port:     port,
		Open:     true,
		Duration: dur,
	}
}

// ScanFunc est la fonction exécutée par chaque worker sur chaque cible
type ScanFunc func(target Target) ScanResult

// RunWorkerPool exécute fn en parallèle sur toutes les cibles avec cfg.Workers goroutines
func RunWorkerPool(targets []Target, cfg *ScanConfig, fn ScanFunc) []ScanResult {
	jobs := make(chan Target, len(targets))
	results := make(chan ScanResult, len(targets))

	var wg sync.WaitGroup
	workers := cfg.Workers
	if workers <= 0 {
		workers = 50
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	// Lancer les workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				results <- fn(t)
			}
		}()
	}

	// Envoyer les jobs
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	// Attendre et fermer les résultats
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

// FilterOpenHosts filtre les résultats pour ne garder que les hôtes avec le port ouvert
func FilterOpenHosts(results []ScanResult) []ScanResult {
	var open []ScanResult
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}
	return open
}

// Helpers

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isNetworkOrBroadcast(ip net.IP, network *net.IPNet) bool {
	// Adresse réseau : tous les bits host à 0
	networkAddr := ip.Mask(network.Mask)
	if ip.Equal(networkAddr) {
		return true
	}

	// Broadcast : tous les bits host à 1
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = networkAddr[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}
