// pkg/models/bloodhound.go

package models

// BHUserEntry représente un utilisateur pour BloodHound CE
type BHUserEntry struct {
	DN             string
	SAMAccountName string
	SID            string
	DomainSID      string
	Domain         string
	SPNs           []string
	Enabled        bool
	PwdNeverExp    bool
	DontReqPreAuth bool
	AdminCount     bool
	LastLogon      int64
	Description    string
}

// BHGroupEntry représente un groupe pour BloodHound CE
type BHGroupEntry struct {
	DN             string
	SAMAccountName string
	SID            string
	DomainSID      string
	Domain         string
	Members        []BHGroupMember
	AdminCount     bool
	Description    string
}

// BHGroupMember représente un membre de groupe pour BloodHound
type BHGroupMember struct {
	ObjectIdentifier string // SID du membre
	ObjectType       string // "User", "Computer", "Group"
}

// BHComputerEntry représente un ordinateur pour BloodHound CE
type BHComputerEntry struct {
	DN               string
	SAMAccountName   string
	SID              string
	DomainSID        string
	Domain           string
	Enabled          bool
	OS               string
	Description      string
	UnconsDelegation bool // Unconstrained delegation
}
