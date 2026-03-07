// pkg/coercion/utils.go

package coercion

// utf16leEncode encode une string en UTF-16LE (pour NDR/RPC)
func utf16leEncode(s string) []byte {
	b := []byte(s)
	out := make([]byte, len(b)*2)
	for i := range b {
		out[i*2] = b[i]
	}
	return out
}
