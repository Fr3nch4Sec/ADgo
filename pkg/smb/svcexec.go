// pkg/smb/svcexec.go
//
// Exécution distante via SMB + SVCCTL (style smbexec d'impacket).
// Flux :
//   1. Connexion SMB → IPC$ → \pipe\svcctl
//   2. DCE/RPC bind sur l'interface SVCCTL
//   3. OpenSCManagerW → handle SC
//   4. CreateServiceW avec cmd : cmd.exe /Q /c <commande> > C:\Windows\Temp\<id>.txt 2>&1
//   5. StartServiceW → exécution
//   6. Attente + lecture du fichier résultat via C$
//   7. DeleteService + cleanup

package smb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/hirochachacha/go-smb2"
)

// ExecResult résultat d'une exécution distante
type ExecResult struct {
	Output   string
	ExitCode int
	Error    error
}

// ExecConfig configuration pour l'exécution distante
type ExecConfig struct {
	Timeout    time.Duration // délai max pour l'exécution (défaut: 15s)
	OutputFile string        // chemin temp sur la cible (auto si vide)
	NoCleanup  bool          // ne pas supprimer le fichier résultat
}

// DefaultExecConfig retourne une configuration par défaut
func DefaultExecConfig() *ExecConfig {
	return &ExecConfig{
		Timeout: 15 * time.Second,
	}
}

// SvcExec exécute une commande sur la cible via SVCCTL SMB.
// Nécessite : droits admin + partage C$ accessible.
func SvcExec(target, username, domain, password string, ntHash []byte, command string, cfg *ExecConfig) (*ExecResult, error) {
	if cfg == nil {
		cfg = DefaultExecConfig()
	}

	// Générer un nom de service et fichier output uniques
	id := randHex(6)
	svcName := "ADGO" + id
	if cfg.OutputFile == "" {
		cfg.OutputFile = `C:\Windows\Temp\` + id + `.txt`
	}

	// 1. Connexion SMB
	conn, err := net.Dial("tcp", target+":445")
	if err != nil {
		return nil, fmt.Errorf("SMB connection failed: %v", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
			Hash:     ntHash,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB auth failed: %v", err)
	}
	defer session.Logoff()

	// 2. Monter IPC$ et ouvrir le pipe SVCCTL
	ipc, err := session.Mount("IPC$")
	if err != nil {
		return nil, fmt.Errorf("IPC$ mount failed: %v", err)
	}
	defer ipc.Umount()

	pipe, err := ipc.Open(`\pipe\svcctl`)
	if err != nil {
		return nil, fmt.Errorf("svcctl pipe open failed: %v", err)
	}
	defer pipe.Close()

	// 3. DCE/RPC bind sur SVCCTL
	if err := rpcBind(pipe); err != nil {
		return nil, fmt.Errorf("SVCCTL bind failed: %v", err)
	}

	// 4. OpenSCManagerW → obtenir un handle SC
	scHandle, err := openSCManager(pipe)
	if err != nil {
		return nil, fmt.Errorf("OpenSCManager failed: %v", err)
	}

	// 5. Construire la commande avec redirection de sortie vers fichier
	fullCmd := fmt.Sprintf(`cmd.exe /Q /c %s > %s 2>&1`, command, cfg.OutputFile)

	// CreateServiceW
	svcHandle, err := createService(pipe, scHandle, svcName, fullCmd)
	if err != nil {
		closeHandle(pipe, scHandle)
		return nil, fmt.Errorf("CreateService failed: %v", err)
	}

	// 6. StartServiceW → exécution
	startErr := startService(pipe, svcHandle)
	// Nettoyer le service même en cas d'erreur
	deleteService(pipe, svcHandle)
	closeHandle(pipe, svcHandle)
	closeHandle(pipe, scHandle)

	if startErr != nil {
		// "Le service ne peut pas être démarré" est normal — la commande s'exécute et se termine
		if !strings.Contains(startErr.Error(), "1053") && !strings.Contains(startErr.Error(), "service did not") {
			return nil, fmt.Errorf("StartService failed: %v", startErr)
		}
	}

	// 7. Attendre l'exécution puis lire le fichier résultat via C$
	time.Sleep(2 * time.Second)

	deadline := time.Now().Add(cfg.Timeout)
	var output string
	for time.Now().Before(deadline) {
		out, err := readOutputFile(session, cfg.OutputFile)
		if err == nil {
			output = out
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Cleanup du fichier résultat
	if !cfg.NoCleanup {
		deleteOutputFile(session, cfg.OutputFile)
	}

	return &ExecResult{Output: strings.TrimRight(output, "\r\n")}, nil
}

// ============================================================
// DCE/RPC helpers
// ============================================================

// SVCCTL interface : 367ABB81-9844-35F1-AD32-98F038001003 v2.0
var svcctlUUID = []byte{
	0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35,
	0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03,
}
var ndrUUID = []byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
}

type rpcPipe interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}

func rpcBind(pipe rpcPipe) error {
	payload := []byte{
		0x05, 0x00, // version
		0x0b,                   // BIND
		0x03,                   // flags
		0x10, 0x00, 0x00, 0x00, // little-endian
		0x48, 0x00, // frag length
		0x00, 0x00, // auth length
		0x01, 0x00, 0x00, 0x00, // call ID
		0xb8, 0x10, 0xb8, 0x10, // max xmit / recv
		0x00, 0x00, 0x00, 0x00, // assoc group
		0x01, 0x00, 0x00, 0x00, // num ctx
		0x00, 0x00, // ctx ID
		0x01, 0x00, // num transfer syntaxes
	}
	payload = append(payload, svcctlUUID...)
	payload = append(payload, 0x02, 0x00, 0x00, 0x00) // version 2.0
	payload = append(payload, ndrUUID...)
	payload = append(payload, 0x02, 0x00, 0x00, 0x00)

	if _, err := pipe.Write(payload); err != nil {
		return err
	}
	resp := make([]byte, 1024)
	n, err := pipe.Read(resp)
	if err != nil || n < 16 || resp[2] != 0x0c {
		return fmt.Errorf("bind_ack not received")
	}
	return nil
}

// rpcRequest envoie une requête DCE/RPC et retourne la réponse
func rpcRequest(pipe rpcPipe, opnum uint16, body []byte) ([]byte, error) {
	fragLen := uint16(24 + len(body))
	header := make([]byte, 24)
	header[0] = 0x05
	header[1] = 0x00
	header[2] = 0x00 // REQUEST
	header[3] = 0x03
	binary.LittleEndian.PutUint32(header[4:], 0x10000000)
	binary.LittleEndian.PutUint16(header[8:], fragLen)
	binary.LittleEndian.PutUint16(header[10:], 0)
	binary.LittleEndian.PutUint32(header[12:], 1)     // call ID
	binary.LittleEndian.PutUint32(header[16:], 0)     // alloc hint
	binary.LittleEndian.PutUint16(header[20:], 0)     // ctx ID
	binary.LittleEndian.PutUint16(header[22:], opnum) // opnum

	payload := append(header, body...)
	if _, err := pipe.Write(payload); err != nil {
		return nil, err
	}

	resp := make([]byte, 65536)
	n, err := pipe.Read(resp)
	if err != nil {
		return nil, err
	}
	if n < 24 {
		return nil, fmt.Errorf("response too short")
	}
	return resp[24:n], nil
}

// openSCManager → OpenSCManagerW (opnum 15)
// retourne un context handle de 20 bytes
func openSCManager(pipe rpcPipe) ([]byte, error) {
	// lpMachineName = NULL, lpDatabaseName = NULL, dwDesiredAccess = SC_MANAGER_ALL_ACCESS (0xF003F)
	body := []byte{
		0x00, 0x00, 0x00, 0x00, // NULL lpMachineName
		0x00, 0x00, 0x00, 0x00, // NULL lpDatabaseName
		0x3f, 0x00, 0x0f, 0x00, // SC_MANAGER_ALL_ACCESS
	}

	resp, err := rpcRequest(pipe, 15, body)
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenSCManager response too short")
	}

	// Les 20 premiers bytes du body de réponse = context handle
	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// createService → CreateServiceW (opnum 12)
func createService(pipe rpcPipe, scHandle []byte, svcName, binPath string) ([]byte, error) {
	body := scHandle // hSCManager

	// lpServiceName (unicode + null)
	body = append(body, ndrWString(svcName)...)
	// lpDisplayName (unicode + null)
	body = append(body, ndrWString(svcName)...)
	// dwDesiredAccess = SERVICE_ALL_ACCESS (0xF01FF)
	body = append(body, 0xff, 0x01, 0x0f, 0x00)
	// dwServiceType = SERVICE_WIN32_OWN_PROCESS (0x10)
	body = append(body, 0x10, 0x00, 0x00, 0x00)
	// dwStartType = SERVICE_DEMAND_START (0x3)
	body = append(body, 0x03, 0x00, 0x00, 0x00)
	// dwErrorControl = SERVICE_ERROR_IGNORE (0x0)
	body = append(body, 0x00, 0x00, 0x00, 0x00)
	// lpBinaryPathName
	body = append(body, ndrWString(binPath)...)
	// lpLoadOrderGroup = NULL
	body = append(body, 0x00, 0x00, 0x00, 0x00)
	// lpdwTagId = NULL
	body = append(body, 0x00, 0x00, 0x00, 0x00)
	// lpDependencies = NULL, dwDependSize = 0
	body = append(body, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// lpServiceStartName = NULL
	body = append(body, 0x00, 0x00, 0x00, 0x00)
	// lpPassword = NULL, dwPwSize = 0
	body = append(body, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	resp, err := rpcRequest(pipe, 12, body)
	if err != nil {
		return nil, err
	}
	if len(resp) < 20 {
		return nil, fmt.Errorf("CreateService response too short")
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// startService → StartServiceW (opnum 19)
func startService(pipe rpcPipe, svcHandle []byte) error {
	body := svcHandle
	body = append(body, 0x00, 0x00, 0x00, 0x00) // dwNumServiceArgs = 0
	body = append(body, 0x00, 0x00, 0x00, 0x00) // lpServiceArgVectors = NULL

	resp, err := rpcRequest(pipe, 19, body)
	if err != nil {
		return err
	}

	// Les 4 derniers bytes = return code
	if len(resp) >= 4 {
		rc := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if rc != 0 && rc != 1053 {
			return fmt.Errorf("StartService returned error code 0x%X", rc)
		}
	}
	return nil
}

// deleteService → DeleteService (opnum 2)
func deleteService(pipe rpcPipe, svcHandle []byte) {
	rpcRequest(pipe, 2, svcHandle) //nolint — best effort
}

// closeHandle → CloseServiceHandle (opnum 0)
func closeHandle(pipe rpcPipe, handle []byte) {
	rpcRequest(pipe, 0, handle) //nolint — best effort
}

// ============================================================
// Lecture du fichier résultat via C$
// ============================================================

func readOutputFile(session *smb2.Session, remotePath string) (string, error) {
	// remotePath = C:\Windows\Temp\xxxx.txt → partage C$, chemin \Windows\Temp\xxxx.txt
	// Extraire la lettre de lecteur
	if len(remotePath) < 3 || remotePath[1] != ':' {
		return "", fmt.Errorf("invalid remote path: %s", remotePath)
	}
	driveLetter := strings.ToUpper(string(remotePath[0]))
	shareName := driveLetter + "$"
	sharePath := strings.ReplaceAll(remotePath[2:], `\`, "/")

	fs, err := session.Mount(shareName)
	if err != nil {
		return "", fmt.Errorf("cannot mount %s: %v", shareName, err)
	}
	defer fs.Umount()

	f, err := fs.Open(sharePath)
	if err != nil {
		return "", fmt.Errorf("output file not ready: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 65536)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}

	return string(buf[:n]), nil
}

func deleteOutputFile(session *smb2.Session, remotePath string) {
	if len(remotePath) < 3 || remotePath[1] != ':' {
		return
	}
	driveLetter := strings.ToUpper(string(remotePath[0]))
	shareName := driveLetter + "$"
	sharePath := strings.ReplaceAll(remotePath[2:], `\`, "/")

	fs, err := session.Mount(shareName)
	if err != nil {
		return
	}
	defer fs.Umount()
	fs.Remove(sharePath) //nolint — best effort
}

// ============================================================
// NDR helpers
// ============================================================

// ndrWString encode une string Unicode (UTF-16LE) + header NDR (length + null)
func ndrWString(s string) []byte {
	runes := utf16.Encode([]rune(s + "\x00"))
	length := uint32(len(runes))

	buf := make([]byte, 12+len(runes)*2)
	binary.LittleEndian.PutUint32(buf[0:], length) // MaxCount
	binary.LittleEndian.PutUint32(buf[4:], 0)      // Offset
	binary.LittleEndian.PutUint32(buf[8:], length) // ActualCount
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[12+i*2:], r)
	}
	return buf
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
