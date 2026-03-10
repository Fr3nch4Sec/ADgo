// pkg/common/utils.go
package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"adgo/pkg/ldap"
)

// DiscoverDC résout automatiquement un Domain Controller via DNS SRV
func DiscoverDC(domain string) (string, error) {
	srvName := "_ldap._tcp.dc._msdcs." + domain
	_, srvs, err := net.LookupSRV("ldap", "tcp", srvName)
	if err != nil {
		return "", fmt.Errorf("DNS SRV lookup failed for %s: %v", srvName, err)
	}
	if len(srvs) == 0 {
		return "", fmt.Errorf("no LDAP SRV records found for %s", domain)
	}

	dcHost := strings.TrimSuffix(srvs[0].Target, ".")
	ips, err := net.LookupIP(dcHost)
	if err != nil {
		return "", fmt.Errorf("failed to resolve IP for %s: %v", dcHost, err)
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %s", dcHost)
}

// ConvertToBloodHoundFormat convertit les données en format BloodHound
func ConvertToBloodHoundFormat(data interface{}) map[string]interface{} {
	switch v := data.(type) {
	case []*ldap.UserEntry:
		return convertUsersToBloodHound(v)
	case []ldap.GroupEntry:
		return convertGroupsToBloodHound(v)
	case []ldap.ComputerEntry:
		return convertComputersToBloodHound(v)
	default:
		return map[string]interface{}{
			"error": "unsupported type for BloodHound conversion",
			"type":  fmt.Sprintf("%T", v),
		}
	}
}

func convertUsersToBloodHound(users []*ldap.UserEntry) map[string]interface{} {
	var bloodHoundData []map[string]interface{}
	for _, user := range users {
		bloodHoundData = append(bloodHoundData, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name":           user.Name,
				"samaccountname": user.SAMAccountName,
				"domain":         ExtractDomainFromDN(user.DN),
			},
			"ObjectIdentifier": GenerateObjectIdentifier(user.DN),
			"ObjectType":       "User",
		})
	}
	return map[string]interface{}{
		"data": bloodHoundData,
		"meta": map[string]interface{}{
			"type":  "users",
			"count": len(users),
		},
	}
}

func convertGroupsToBloodHound(groups []ldap.GroupEntry) map[string]interface{} {
	var bloodHoundData []map[string]interface{}
	for _, group := range groups {
		bloodHoundData = append(bloodHoundData, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name":   group.Name,
				"domain": ExtractDomainFromDN(group.DN),
			},
			"ObjectIdentifier": GenerateObjectIdentifier(group.DN),
			"ObjectType":       "Group",
		})
	}
	return map[string]interface{}{
		"data": bloodHoundData,
		"meta": map[string]interface{}{
			"type":  "groups",
			"count": len(groups),
		},
	}
}

func convertComputersToBloodHound(computers []ldap.ComputerEntry) map[string]interface{} {
	var bloodHoundData []map[string]interface{}
	for _, computer := range computers {
		bloodHoundData = append(bloodHoundData, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name":   computer.Name,
				"domain": ExtractDomainFromDN(computer.DN),
			},
			"ObjectIdentifier": GenerateObjectIdentifier(computer.DN),
			"ObjectType":       "Computer",
		})
	}
	return map[string]interface{}{
		"data": bloodHoundData,
		"meta": map[string]interface{}{
			"type":  "computers",
			"count": len(computers),
		},
	}
}

// ExtractDomainFromDN extrait le domaine depuis un DN
func ExtractDomainFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "DC=") {
			return strings.TrimPrefix(part, "DC=")
		}
	}
	return ""
}

// GenerateObjectIdentifier génère un identifiant unique
func GenerateObjectIdentifier(dn string) string {
	hash := sha256.Sum256([]byte(dn))
	return hex.EncodeToString(hash[:])
}
