
# ADgo - Active Directory Pentesting Toolkit in Go


**ADgo** is an audit and penetration testing tool for **Active Directory**, written in Go.

 It allows you to enumerate, exploit, and analyze **AD environments** with advanced features such as **BloodHound** conversion, **NTLM/Kerberos** attacks, and much more..

---
  

## 📋 Main Features

=======

### 📋 Orders Available


| **Catégorie**         | **Commandes**                                                                                     | **Description**                                                                                     |
|-----------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **LDAP**              | `ldap users`, `ldap groups`, `ldap computers`, `ldap spns`, `ldap asreproast`, `ldap password-policy` | Énumération des utilisateurs, groupes, ordinateurs, SPNs, et politiques de mot de passe.           |
| **SMB**               | `smb shares`, `smb download`, `smb upload`                                                     | Gestion des partages SMB, téléchargement et upload de fichiers.                                   |
| **NTLM**              | `ntlm ntlmv1`, `ntlm ntlmv2`, `ntlm ntlmrelay`                                                  | Authentification et relay NTLM.                                                                    |
| **Kerberos**          | `kerberos kerberoast`, `kerberos goldenticket`, `kerberos silverticket`                          | Attaques Kerberos (Kerberoasting, Golden/Silver Ticket).                                          |
| **Exploits**          | `exploits zerologon`                                                                           | Exploitation de vulnérabilités (ex: ZeroLogon).                                                     |
| **Persistence**       | `persistence add-admin-user`, `persistence dump-ntlm`                                           | Techniques de persistance (ajout d'utilisateurs admin, dump de hashs NTLM).                       |
| **Mouvement Latéral** | `lateral-movement pth`, `lateral-movement psexec`                                            | Pass-the-Hash et exécution de commandes via PSExec.                                                 |
| **RPC**               | `rpc enumerate`, `rpc script`                                                                 | Énumération et exécution de scripts RPC.                                                            |
| **WinRM**             | `winrm exec`                                                                                   | Exécution de commandes via WinRM.                                                                    |
| **WMI**               | `wmi query`                                                                                   | Requêtes WMI pour récupérer des informations système.                                              |
| **Coercion NTLM**     | `coercion`                                                                           			| Serveur de coercion NTLM.                                                                          |



## 🛠 Installation

### Prerequisites

- **Go 1.20+** (to compile the project).

- **Git** (to clone the repository).

- **Go Dependencies** (installed automatically with `go mod tidy`).

  

### Steps


1. **Clone the repository** :   

  ```bash
  git clone https://github.com/Fr3nch4Sec/adgo.git
  
  cd adgo
  
  go mod tidy
  
  go build ./...
  
  ./adgo --help`
  ```


## Commandes de Base

| Commande                     | Description                           |
| ---------------------------- | --------------------------------------|
| `./adgo ldap users`          | Lists the LDAP users.                 |
| `./adgo ldap groups`         | List the LDAP groups.                 |
| `./adgo ldap computers`      | Eenumerates LDAP computers.           |
| `./adgo smb shares`          | List of SMB shares.                   |
| `./adgo kerberos kerberoast` | Performs a Kerberoasting attack.      |
| `./adgo ntlm ntlmrelay`      | Start an NTLM relay server.           |
| `./adgo exploits zerologon`  | Exploits the ZeroLogon vulnerability. |



## Global Options

|Option|Description|
|---|---|
|`--debug`|Enables debug mode.|
|`--json`|Displays the output in JSON format.|
|`--bloodhound`|Generate a file compatible with BloodHound (for `ldap users`, `ldap groups`, `ldap computers`).|


======


## Examples of Use


* #### 1. LDAP enumeration with BloodHound

```bash
./adgo ldap users --bloodhound
```

Generate a file `bloodhound_users.json` compatible with [BloodHound](https://github.com/BloodHoundAD/BloodHound).


* #### 2. ZeroLogon Exploitation

```bash
./adgo exploits zerologon --target 192.168.1.10 --script ../../scripts/exploits/zerologon/zerologon.py`
```

Exploits the **ZeroLogon** vulnerability on a target domain controller.


* #### 3. Pass-the-Hash

```bash
./adgo lateral-movement pth --target 192.168.1.10 --username administrator --nthash a1b2c3d4e5f6...`
```

Perform an attack **Pass-the-Hash** on a target machine.


* #### 4. Énumération SMB

```bash
./adgo smb shares --server 192.168.1.10 --username administrator --password password123`
```

List of accessible SMB shares.

=======
```bash

adgo/
├── cmd/
│   └── adgo/            # Commandes CLI (Cobra)
├── pkg/
│   ├── common/          # Fonctions communes (logs, erreurs, credentials)
│   ├── configuration/   # Gestion de la configuration
│   ├── ldap/            # Fonctions LDAP
│   ├── smb/             # Fonctions SMB
│   ├── ntlm/            # Fonctions NTLM
│   ├── kerberos/        # Fonctions Kerberos
│   ├── exploits/        # Exploits (ZeroLogon, etc.)
│   └── ...              # Autres modules
├── scripts/             # Scripts externes (ex: ZeroLogon en Python)
└── go.mod               # Dépendances Go

=======

```


### 🛡Sécurité et Bonnes Pratiques

- **Respect the laws** : ADGo is an auditing tool. **Use it only on systems for which you have permission.**.



### 🚀 Contribuer

Contributions are welcome! To contribute :


### 📜 Licence

This project is licensed **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.


## 📬 Contact
For any questions or suggestions, contact me on :

- **GitHub** : [@Fr3nch4Sec](https://github.com/Fr3nch4Sec)
- **Mail** : [(yoanncoudry494@gmail.com)]



**⚠️** **Warning** : This tool is intended for **legal and authorized tests**. The author accepts no responsibility for misuse.
