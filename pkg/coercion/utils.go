// pkg/coercion/utils.go

package coercion

import (
	"encoding/binary"
	"unicode/utf16"
)

// utf16leEncode encode une string en UTF-16LE (pour NDR/RPC)
func utf16leEncode(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}

	return buf
}
