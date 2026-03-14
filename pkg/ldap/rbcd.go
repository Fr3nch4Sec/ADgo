// pkg/ldap/rbcd.go
//
// Wrapper RBCD exposé depuis pkg/ldap pour être utilisé par les commandes CLI
// sans dépendance directe sur pkg/adattack.
//
// pkg/adattack contient l'implémentation réelle (SetupRBCD, ReadRBCD, ClearRBCD).
// Ce fichier fournit NewRBCDClient() qui prend un *ldap.Conn et délègue.

package ldap

import (
	"adgo/pkg/adattack"

	goldap "github.com/go-ldap/ldap/v3"
)

// RBCDClient wraps adattack.RBCDClient pour l'exposer depuis pkg/ldap
type RBCDClient struct {
	inner *adattack.RBCDClient
}

// RBCDResult résultat d'un SetupRBCD
type RBCDResult = adattack.RBCDResult

// NewRBCDClient crée un client RBCD à partir d'une connexion LDAP.
// Prend un *goldap.Conn (obtenu via ldap.Client.Conn()).
func NewRBCDClient(conn *goldap.Conn, baseDN string) *RBCDClient {
	return &RBCDClient{
		inner: adattack.NewRBCDClient(conn, baseDN),
	}
}

// SetupRBCD configure RBCD sur targetComputer pour attackerAccount.
func (r *RBCDClient) SetupRBCD(targetComputer, attackerAccount string) (*RBCDResult, error) {
	return r.inner.SetupRBCD(targetComputer, attackerAccount)
}

// ReadRBCD lit la configuration RBCD actuelle d'un ordinateur.
// Retourne la liste des SIDs autorisés.
func (r *RBCDClient) ReadRBCD(targetComputer string) ([]string, error) {
	return r.inner.ReadRBCD(targetComputer)
}

// ClearRBCD supprime la configuration RBCD d'un ordinateur (cleanup).
func (r *RBCDClient) ClearRBCD(targetComputer string) error {
	return r.inner.ClearRBCD(targetComputer)
}
