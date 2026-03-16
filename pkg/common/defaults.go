// pkg/common/defaults.go
//
// Variables globales injectées depuis la config persistante (~/.adgo/config.yaml)
// Ces valeurs sont utilisées comme fallback quand le flag CLI correspondant
// n'est pas fourni.

package common

// DefaultDCIP adresse IP du DC par défaut (depuis ~/.adgo/config.yaml)
// Utilisée par toutes les commandes qui ont un flag --dc-ip
var DefaultDCIP string
