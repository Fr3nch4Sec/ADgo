
# ADgo - Active Directory Pentesting Toolkit in Go


**ADgo** est un outil d'audit et de pentest pour **Active Directory**, écrit en Go.

 Il permet d'énumérer, exploiter et analyser les environnements AD avec des fonctionnalités avancées comme la **conversion BloodHound**, les attaques **NTLM/Kerberos**, et bien plus.

---
  

## 📋 Fonctionnalités Principales

=======

### 📋 Commandes Disponibles


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


### Prérequis

- **Go 1.20+** (pour compiler le projet).

- **Git** (pour cloner le dépôt).

- **Dépendances Go** (installées automatiquement avec `go mod tidy`).

  

### Étapes


1. **Cloner le dépôt** :   

  ```bash
  git clone https://github.com/Fr3nch4Sec/adgo.git
  
  cd adgo
  
  go mod tidy
  
  go build ./...
  
  ./adgo --help`
  ```


## Commandes de Base

| Commande                     | Description                          |
| ---------------------------- | ------------------------------------ |
| `./adgo ldap users`          | Énumère les utilisateurs LDAP.       |
| `./adgo ldap groups`         | Énumère les groupes LDAP.            |
| `./adgo ldap computers`      | Énumère les ordinateurs LDAP.        |
| `./adgo smb shares`          | Liste les partages SMB.              |
| `./adgo kerberos kerberoast` | Effectue une attaque Kerberoasting.  |
| `./adgo ntlm ntlmrelay`      | Démarre un serveur de relay NTLM.    |
| `./adgo exploits zerologon`  | Exploite la vulnérabilité ZeroLogon. |



## Options Globales

|Option|Description|
|---|---|
|`--debug`|Active le mode debug.|
|`--json`|Affiche la sortie en format JSON.|
|`--bloodhound`|Génère un fichier compatible avec BloodHound (pour `ldap users`, `ldap groups`, `ldap computers`).|


=======


## Exemples d'Utilisation


* #### 1. Énumération LDAP avec BloodHound

```bash
./adgo ldap users --bloodhound
```

Génère un fichier `bloodhound_users.json` compatible avec [BloodHound](https://github.com/BloodHoundAD/BloodHound).


* #### 2. Exploitation ZeroLogon

```bash
./adgo exploits zerologon --target 192.168.1.10 --script ../../scripts/exploits/zerologon/zerologon.py`
```

Exploite la vulnérabilité **ZeroLogon** sur un contrôleur de domaine cible.


* #### 3. Pass-the-Hash

```bash
./adgo lateral-movement pth --target 192.168.1.10 --username administrator --nthash a1b2c3d4e5f6...`
```

Effectue une attaque **Pass-the-Hash** sur une machine cible.


* #### 4. Énumération SMB

```bash
./adgo smb shares --server 192.168.1.10 --username administrator --password password123`
```

Liste les partages SMB accessibles.




=======
```bash
>>>>>>> ba860c32a726d42d00833988de759e7187937214
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


=======
```


### 🛡Sécurité et Bonnes Pratiques

- **Ne jamais commiter de mots de passe** : Utilise des variables d’environnement ou des fichiers de configuration chiffrés (ex: `config.yaml` avec `sops`).
- **Tester dans un environnement isolé** : Utilise des machines virtuelles (ex: Kali Linux) pour éviter d’impacter un réseau de production.
- **Respecter les lois** : ADGo est un outil d’audit. **Utilise-le uniquement sur des systèmes dont tu as l’autorisation**.



### 🚀 Contribuer

Les contributions sont les bienvenues ! Pour contribuer :


### 📜 Licence

Ce projet est sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.


## 📬 Contact

Pour toute question ou suggestion, contacte-moi sur :

- **GitHub** : [@Fr3nch4Sec](https://github.com/Fr3nch4Sec)
- **Mail** : [(yoanncoudry494@gmail.com)]



**⚠️ Avertissement** : Cet outil est destiné à des **tests légaux et autorisés**. L'auteur décline toute responsabilité en cas de mauvaise utilisation.
