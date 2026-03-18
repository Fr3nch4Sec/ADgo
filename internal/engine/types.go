package engine

import "fmt"

// LDAPEnum est un module de démo (factice).
// Il sert uniquement à illustrer comment brancher des modules dans le moteur.
type LDAPEnum struct{}

func (m LDAPEnum) Run(ctx *Context, input map[string]interface{}) (Result, error) {
	fmt.Println("[+] Enumerating users...")

	return Result{
		Success: true,
		Data: map[string]interface{}{
			"users": []string{"admin", "user1", "guest"},
		},
	}, nil
}

// SMBLogin est un module de démo (factice).
type SMBLogin struct{}

func (m SMBLogin) Run(ctx *Context, input map[string]interface{}) (Result, error) {
	users, _ := input["users"].([]string)

	successUsers := []string{}
	for _, u := range users {
		if u == "admin" {
			successUsers = append(successUsers, u)
		}
	}

	return Result{
		Success: len(successUsers) > 0,
		Data: map[string]interface{}{
			"valid_users": successUsers,
		},
	}, nil
}

