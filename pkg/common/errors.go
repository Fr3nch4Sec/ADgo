// pkg/common/errors.go
package common

import "fmt"

// WrapError encapsule une erreur avec un message contextuel.
func WrapError(message string, err error) error {
	return fmt.Errorf("%s: %w", message, err)
}

// MaskPasswords masque les mots de passe dans une structure.
func MaskPasswords(creds *Credentials) *Credentials {
	masked := *creds
	masked.Password = "*****"
	masked.SMBPassword = "*****"
	return &masked
}
