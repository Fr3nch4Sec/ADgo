// pkg/models/ad.go

package models

import "time"

// User représente un utilisateur Active Directory (type canonique)
type User struct {
	DN               string    `json:"dn"`
	Name             string    `json:"name"`
	SAMAccountName   string    `json:"samaccountname"`
	SID              string    `json:"objectsid,omitempty"`
	PrimaryGroupID   string    `json:"primarygroupid,omitempty"`
	SPNs             []string  `json:"spns,omitempty"`
	Groups           []string  `json:"groups,omitempty"`
	Enabled          bool      `json:"enabled"`
	AdminCount       int       `json:"admincount,omitempty"`
	PasswordNeverExp bool      `json:"password_never_expires"`
	LastLogon        time.Time `json:"last_logon"`
	PwdLastSet       time.Time `json:"pwd_last_set"`
	AccountControl   string    `json:"account_control,omitempty"`
}

// Group représente un groupe Active Directory (type canonique)
type Group struct {
	DN             string   `json:"dn"`
	Name           string   `json:"name"`
	SAMAccountName string   `json:"samaccountname,omitempty"`
	SID            string   `json:"objectsid,omitempty"`
	Members        []string `json:"members,omitempty"`
	Description    string   `json:"description,omitempty"`
}

// Computer représente un ordinateur Active Directory (type canonique)
type Computer struct {
	DN              string    `json:"dn"`
	Name            string    `json:"name"`
	SAMAccountName  string    `json:"samaccountname,omitempty"`
	SID             string    `json:"objectsid,omitempty"`
	OperatingSystem string    `json:"operatingsystem,omitempty"`
	OSVersion       string    `json:"osversion,omitempty"`
	LastLogon       time.Time `json:"last_logon"`
	Enabled         bool      `json:"enabled"`
}

// OrgUnit représente une unité organisationnelle
type OrgUnit struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UserHash représente un utilisateur avec son hash NTLM (pour secretsdump)
type UserHash struct {
	DN             string `json:"dn"`
	SAMAccountName string `json:"samaccountname"`
	NTLMHash       string `json:"ntlm_hash"`
	LMHash         string `json:"lm_hash,omitempty"`
}

// PasswordPolicy représente la politique de mot de passe du domaine
type PasswordPolicy struct {
	MinPasswordLength      int  `json:"min_password_length"`
	PasswordHistorySize    int  `json:"password_history_size"`
	MaxPasswordAgeDays     int  `json:"max_password_age_days"`
	MinPasswordAgeDays     int  `json:"min_password_age_days"`
	LockoutThreshold       int  `json:"lockout_threshold"`
	LockoutDurationMinutes int  `json:"lockout_duration_minutes"`
	ComplexityEnabled      bool `json:"complexity_enabled"`
}
