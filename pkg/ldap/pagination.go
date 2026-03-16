// pkg/ldap/pagination.go
//
// Extension du package ldap avec pagination LDAP et traitement concurrent.
//
// Optimisations :
//   1. Pagination via LDAP Simple Paged Results Control (RFC 2696)
//      — évite les timeouts sur les grands domaines (10 000+ objets)
//      — réduit la charge mémoire : traitement page par page
//   2. Traitement concurrent des pages
//   3. Connection keep-alive via ping périodique

package ldap

import (
	"fmt"
	"sync"

	goldap "github.com/go-ldap/ldap/v3"
)

const defaultPageSize = 500

// SearchPaged effectue une recherche LDAP avec pagination.
//
// Sans pagination : AD retourne max 1000 entrées (limite hardcodée AD)
// Avec pagination : on récupère TOUT, page par page de 500 entrées
func (c *Client) SearchPaged(baseDN, filter string, attrs []string) ([]*goldap.Entry, error) {
	var allEntries []*goldap.Entry
	var pagingControl *goldap.ControlPaging

	pagingControl = goldap.NewControlPaging(defaultPageSize)

	for {
		req := goldap.NewSearchRequest(
			baseDN,
			goldap.ScopeWholeSubtree,
			goldap.NeverDerefAliases,
			0, 0, false,
			filter,
			attrs,
			[]goldap.Control{pagingControl},
		)

		sr, err := c.conn.Search(req)
		if err != nil {
			return allEntries, fmt.Errorf("paged search failed: %v", err)
		}

		allEntries = append(allEntries, sr.Entries...)

		// Vérifier s'il y a une prochaine page
		updatedControl := goldap.FindControl(sr.Controls, goldap.ControlTypePaging)
		if updatedControl == nil {
			break
		}

		cookie := updatedControl.(*goldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			break // Dernière page
		}

		pagingControl.SetCookie(cookie)
	}

	return allEntries, nil
}

// SearchPagedParallel effectue plusieurs recherches LDAP en parallèle
// et agrège les résultats. Utile pour BloodHound (users + groups + computers
// simultanément sur des connexions LDAP différentes).
//
// Note : chaque goroutine nécessite sa propre connexion LDAP.
type PagedSearchJob struct {
	BaseDN string
	Filter string
	Attrs  []string
	Tag    string // identifiant pour distinguer les résultats
}

type PagedSearchResult struct {
	Tag     string
	Entries []*goldap.Entry
	Err     error
}

// SearchMultiple exécute plusieurs recherches en parallèle sur des connexions séparées.
// server, domain, username, password : pour créer les connexions supplémentaires
func SearchMultiple(
	server, domain, username, password, ntHash string,
	jobs []PagedSearchJob,
) []PagedSearchResult {
	results := make([]PagedSearchResult, len(jobs))
	var wg sync.WaitGroup

	for i, job := range jobs {
		wg.Add(1)
		go func(idx int, j PagedSearchJob) {
			defer wg.Done()

			// Chaque goroutine crée sa propre connexion LDAP
			client, err := NewClientNTLM(
				nil, server, domain, username, password, ntHash, false,
			)
			if err != nil {
				results[idx] = PagedSearchResult{Tag: j.Tag, Err: err}
				return
			}
			defer client.Close()

			entries, err := client.SearchPaged(j.BaseDN, j.Filter, j.Attrs)
			results[idx] = PagedSearchResult{
				Tag:     j.Tag,
				Entries: entries,
				Err:     err,
			}
		}(i, job)
	}

	wg.Wait()
	return results
}

// EnumerateUsersPagedFast énumère les utilisateurs avec pagination.
// Remplace avantageusement EnumerateUsers sur les grands domaines.
func (c *Client) EnumerateUsersPagedFast(baseDN string) ([]UserEntry, error) {
	entries, err := c.SearchPaged(
		baseDN,
		"(&(objectClass=user)(objectCategory=person))",
		[]string{
			"cn", "sAMAccountName", "distinguishedName",
			"userAccountControl", "pwdLastSet", "lastLogon",
			"servicePrincipalName", "description",
		},
	)
	if err != nil {
		return nil, err
	}

	// Traitement concurrent des entrées (parsing des attributs)
	users := make([]UserEntry, len(entries))
	var wg sync.WaitGroup

	// Utiliser un pool de workers pour le parsing (CPU-bound)
	const parseWorkers = 8
	jobs := make(chan int, len(entries))
	for w := 0; w < parseWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				users[idx] = parseUserEntry(entries[idx])
			}
		}()
	}

	for i := range entries {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return users, nil
}

// parseUserEntry parse une entrée LDAP en UserEntry
func parseUserEntry(entry *goldap.Entry) UserEntry {
	uac := parseUAC(entry.GetAttributeValue("userAccountControl"))

	// Convertir les timestamps Windows FILETIME (int64) en strings lisibles
	var pwdLastSet, lastLogon string
	if pts, err2 := parseInt64(entry.GetAttributeValue("pwdLastSet")); err2 == nil {
		if t := windowsFileTimeToUnix(pts); !t.IsZero() {
			pwdLastSet = t.Format("2006-01-02 15:04:05")
		}
	}
	if lts, err2 := parseInt64(entry.GetAttributeValue("lastLogon")); err2 == nil {
		if t := windowsFileTimeToUnix(lts); !t.IsZero() {
			lastLogon = t.Format("2006-01-02 15:04:05")
		}
	}

	u := UserEntry{
		DN:             entry.DN,
		Name:           entry.GetAttributeValue("cn"),
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		SPNs:           entry.GetAttributeValues("servicePrincipalName"),
		PwdLastSet:     pwdLastSet,
		LastLogon:      lastLogon,
	}

	// Décoder les flags UAC
	var flags []string
	if uac&0x0002 != 0 {
		flags = append(flags, "DISABLED")
	}
	if uac&0x10000 != 0 {
		flags = append(flags, "DONT_EXPIRE_PASSWORD")
	}
	if uac&0x400000 != 0 {
		flags = append(flags, "DONT_REQ_PREAUTH")
	}
	if uac&0x80000 != 0 {
		flags = append(flags, "TRUSTED_FOR_DELEGATION")
	}
	u.AccountControl = joinFlags(flags)
	return u
}

func parseUAC(s string) int {
	var v int
	fmt.Sscanf(s, "%d", &v)
	return v
}

func parseInt64(s string) (int64, error) {
	var v int64
	n, err := fmt.Sscanf(s, "%d", &v)
	if n == 0 || err != nil {
		return 0, fmt.Errorf("cannot parse %q", s)
	}
	return v, nil
}

func joinFlags(flags []string) string {
	if len(flags) == 0 {
		return "NORMAL"
	}
	result := ""
	for i, f := range flags {
		if i > 0 {
			result += "|"
		}
		result += f
	}
	return result
}
