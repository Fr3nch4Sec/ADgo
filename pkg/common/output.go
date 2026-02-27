// pkg/common/output.go
package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"adgo/pkg/ldap"
)

// extractDomainFromDN extrait le domaine depuis un DN.
func extractDomainFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "DC=") {
			return strings.TrimPrefix(part, "DC=")
		}
	}
	return ""
}

// generateObjectIdentifier génère un identifiant unique.
func generateObjectIdentifier(dn string) string {
	hash := sha256.Sum256([]byte(dn))
	return hex.EncodeToString(hash[:])
}

func printBloodHound(data interface{}) {
	var bloodHoundData []map[string]interface{}
	var outputFile = "bloodhound_output.json"

	switch v := data.(type) {
	case []ldap.UserEntry:
		for _, user := range v {
			bloodHoundData = append(bloodHoundData, map[string]interface{}{
				"Properties": map[string]interface{}{
					"name":                    user.Name,
					"domain":                  extractDomainFromDN(user.DN),
					"enabled":                 true,
					"passwordneverexpires":    false,
					"unconstraineddelegation": false,
					"serviceprincipalnames":   user.SPNs,
				},
				"ObjectIdentifier": generateObjectIdentifier(user.DN),
			})
		}
		outputFile = "bloodhound_users.json"
	case []ldap.GroupEntry:
		for _, group := range v {
			bloodHoundData = append(bloodHoundData, map[string]interface{}{
				"Properties": map[string]interface{}{
					"name":   group.Name,
					"domain": extractDomainFromDN(group.DN),
				},
				"ObjectIdentifier": generateObjectIdentifier(group.DN),
			})
		}
		outputFile = "bloodhound_groups.json"
	default:
		fmt.Println("Unsupported data type for BloodHound output")
		return
	}

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Failed to create BloodHound output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bloodHoundData); err != nil {
		fmt.Printf("Failed to write BloodHound output: %v\n", err)
		return
	}

	fmt.Printf("BloodHound output written to %s\n", outputFile)
}
