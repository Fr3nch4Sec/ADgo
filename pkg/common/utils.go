// pkg/common/utils.go
package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"adgo/pkg/ldap"

	"gopkg.in/yaml.v3"
)

// PrintError affiche une erreur.
func PrintError(err error) {
	log.Printf("[ERROR] %v\n", err)
}

// PrintSuccess affiche un message de succès.
func PrintSuccess(message string) {
	log.Printf("[SUCCESS] %s\n", message)
}

// PrintInfo affiche un message d'information.
func PrintInfo(message string) {
	log.Printf("[INFO] %s\n", message)
}

// PrintDebug affiche un message de débogage.
func PrintDebug(message string, debug bool) {
	if debug {
		log.Printf("[DEBUG] %s\n", message)
	}
}

// PrintOutput affiche la sortie formatée.
func PrintOutput(data interface{}, bloodhound bool, jsonOut bool, debug bool) {
	if jsonOut {
		if bloodhound {
			jsonData, err := json.MarshalIndent(ConvertToBloodHoundFormat(data), "", "  ")
			if err != nil {
				PrintError(fmt.Errorf("failed to marshal JSON: %v", err))
				return
			}
			fmt.Println(string(jsonData))
		} else {
			jsonData, err := json.MarshalIndent(data, "", "  ")
			if err != nil {
				PrintError(fmt.Errorf("failed to marshal JSON: %v", err))
				return
			}
			fmt.Println(string(jsonData))
		}
	} else {
		fmt.Println(data)
	}
}

// ConvertToBloodHoundFormat convertit les données au format BloodHound.
func ConvertToBloodHoundFormat(data interface{}) interface{} {
	switch v := data.(type) {
	case []ldap.UserEntry:
		var bloodHoundUsers []map[string]interface{}
		for _, user := range v {
			bloodHoundUser := map[string]interface{}{
				"Properties": map[string]interface{}{
					"name":                    user.Name,
					"domain":                  ExtractDomainFromDN(user.DN),
					"enabled":                 true,
					"passwordneverexpires":    false,
					"unconstraineddelegation": false,
					"serviceprincipalnames":   user.SPNs,
				},
				"ObjectIdentifier": GenerateObjectIdentifier(user.DN),
			}
			bloodHoundUsers = append(bloodHoundUsers, bloodHoundUser)
		}
		return map[string]interface{}{
			"data": bloodHoundUsers,
			"meta": map[string]interface{}{
				"type":  "users",
				"count": len(bloodHoundUsers),
			},
		}
	case []ldap.GroupEntry:
		var bloodHoundGroups []map[string]interface{}
		for _, group := range v {
			bloodHoundGroup := map[string]interface{}{
				"Properties": map[string]interface{}{
					"name":   group.Name,
					"domain": ExtractDomainFromDN(group.DN),
				},
				"ObjectIdentifier": GenerateObjectIdentifier(group.DN),
			}
			bloodHoundGroups = append(bloodHoundGroups, bloodHoundGroup)
		}
		return map[string]interface{}{
			"data": bloodHoundGroups,
			"meta": map[string]interface{}{
				"type":  "groups",
				"count": len(bloodHoundGroups),
			},
		}
	case []ldap.ComputerEntry:
		var bloodHoundComputers []map[string]interface{}
		for _, computer := range v {
			bloodHoundComputer := map[string]interface{}{
				"Properties": map[string]interface{}{
					"name":                    computer.Name,
					"domain":                  ExtractDomainFromDN(computer.DN),
					"enabled":                 true,
					"unconstraineddelegation": false,
				},
				"ObjectIdentifier": GenerateObjectIdentifier(computer.DN),
			}
			bloodHoundComputers = append(bloodHoundComputers, bloodHoundComputer)
		}
		return map[string]interface{}{
			"data": bloodHoundComputers,
			"meta": map[string]interface{}{
				"type":  "computers",
				"count": len(bloodHoundComputers),
			},
		}
	default:
		return data
	}
}

// ExtractDomainFromDN extrait le domaine depuis un DN.
func ExtractDomainFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "DC=") {
			return strings.TrimPrefix(part, "DC=")
		}
	}
	return ""
}

// LoadCredentials charge les identifiants depuis un fichier YAML.
func LoadCredentials() (*Credentials, error) {
	data, err := os.ReadFile("configs/config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var creds Credentials
	err = yaml.Unmarshal(data, &creds)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	return &creds, nil
}

// GenerateObjectIdentifier génère un identifiant unique.
func GenerateObjectIdentifier(dn string) string {
	hash := sha256.Sum256([]byte(dn))
	return hex.EncodeToString(hash[:])
}
