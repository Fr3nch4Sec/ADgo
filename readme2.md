# ADgo - Active Directory Tooling in Go

[![Go](https://img.shields.io/badge/Go-1.20+-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/Fr3nch4Sec/ADgo)](https://github.com/Fr3nch4Sec/ADgo/releases)

**ADgo** est un outil en ligne de commande écrit en Go pour les tests d'intrusion et l'audit des environnements **Active Directory**. Il permet d'énumérer, exploiter et analyser les configurations AD de manière **modulaire**, **rapide** et **discrète**.

---

## 📋 Fonctionnalités Principales
   Module               | Description                                                                                     | Commande Exemple                                                                 |
 |----------------------|-------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
 | **LDAP**             | Énumération avancée des utilisateurs, groupes, ordinateurs et politiques de mot de passe.     | `adgo ldap users --filter "name=*admin*" --csv admins.csv`                      |
 | **Kerberos**         | Attaques Kerberoasting, Golden/Silver Tickets (en développement).                              | `adgo kerberos kerberoast`                                                      |
 | **NTLM**             | Coercion NTLM, relay, et exploitation des vulnérabilités (PetitPotam, etc.).                  | `adgo ntlm coercion --technique petitpotam`                                     |
 | **Exploits**         | Exploitation de vulnérabilités connues (ZeroLogon, etc.).                                      | `adgo exploits zerologon --target dc01`                                        |
 | **BloodHound**       | Export des données au format BloodHound pour une analyse graphique.                          | `adgo ldap users --bloodhound`                                                 |
 | **Rapport CSV/JSON** | Génération de rapports détaillés pour les audits.                                            | `adgo ldap users --csv report.csv`                                             |

---

## 🚀 Installation

### Prérequis
- **Go 1.20+** ([Téléchargement](https://go.dev/dl/))
- **Git** ([Téléchargement](https://git-scm.com/downloads))

### Depuis les Sources
```bash
git clone https://github.com/Fr3nch4Sec/ADgo.git
cd ADgo
go build -o adgo ./cmd/adgo

Binaire Précompilé
Télécharge la dernière version depuis les releases GitHub.

## 🛠️ Utilisation

### 📜 Énumération LDAP

#### Lister tous les utilisateurs
```bash
./adgo ldap users -u DOMAIN\\user -p password -d domain.local

### Filtrer les utilisateurs


                Option         |                    Description                                 |             Exemple
|------------------------------|----------------------------------------------------------------|---------------------------------------------|
|    --filter                  |         Filtre LDAP personnalisé.                              |     --filter "name=*admin*"
|    --disabled-only                        Liste uniquement les comptes désactivés.                --disabled-only --csv disabled_users.csv
|    --csv                                  Exporte les résultats en CSV.                                       --csv users.csv
|    --json                                     Sortie formatée en JSON.                                           --json
|    --bloodhound                               Exporte au format BloodHound.                                   --bloodhound
  


#### Exemple complet :
```bash
./adgo ldap users --filter "name=*admin*" --csv admins.csv --disabled-only

#### Exemple de Sortie CSV
```csv
DN,Name,SAMAccountName,LastLogon,AccountControl,PwdLastSet,SPNs
"CN=Admin,DC=lab,DC=local",Admin,admin,2026-03-02 14:30:00,,2026-01-01 10:00:00,
"CN=Service,DC=lab,DC=local",Service Account,svc_account,Never,DISABLED,2025-12-01 09:00:00,MSSQLSvc/sql01.lab.local```

#### Exemple de Sortie BloodHound
```json
[
  {
    "Properties": {
      "name": "Admin",
      "samaccountname": "admin",
      "lastlogon": "2026-03-02 14:30:00",
      "enabled": true,
      "passwordlastset": "2026-01-01 10:00:00",
      "spns": []
    },
    "ObjectType": "User"
  }
]```


#### Lister les groupes
```bash
./adgo ldap groups --json```

#### Lister les ordinateurs
```bash
./adgo ldap computers --csv computers.csv```

#### Lister les utilisateurs avec SPN (Kerberoasting)
```bash
./adgo ldap spns --bloodhound```

#### Récupérer la politique de mot de passe
```bash
./adgo ldap password-policy```


### 🔑 Kerberos (en développement)

# Kerberoasting (à venir)
```bash
./adgo kerberos kerberoast```

# Golden Ticket (à venir)
```bash
./adgo kerberos golden --user Administrator --domain lab.local --sid S-1-5-21-... --krbtgt-hash ...```


### 🔄 NTLM

# Coercion NTLM (ex: PetitPotam)
```bash
./adgo ntlm coercion --technique petitpotam --listener smb```


### 📊 Exemples Concrets

- Scénario 1 : Audit des Comptes Désactivés

# 1. Lister tous les comptes désactivés
./adgo ldap users --disabled-only --csv disabled_users.csv

# 2. Analyser avec BloodHound
./adgo ldap users --disabled-only --bloodhound

- Scénario 2 : Recherche de Comptes Sensibles

# 1. Filtrer les utilisateurs avec des SPNs (pour Kerberoasting)
./adgo ldap users --filter "(servicePrincipalName=*)" --csv spn_users.csv

# 2. Exporter en JSON pour analyse
./adgo ldap users --filter "(servicePrincipalName=*)" --json > spn_users.json

- Scénario 3 : Rapport Complet

# Générer un rapport CSV complet
```bash
./adgo ldap users --csv full_report.csv
./adgo ldap groups --csv full_report_groups.csv
./adgo ldap computers --csv full_report_computers.csv```


### 🎯 Roadmap





  
    
      Fonctionnalité
      Statut
      Version Cible
    
  
  
    
      Énumération LDAP avancée
      ✅ Terminée
      v1.1.0
    
    
      Filtrage des comptes désactivés
      ✅ Terminée
      v1.1.0
    
    
      Export CSV/JSON/BloodHound
      ✅ Terminée
      v1.1.0
    
    
      Kerberoasting automatisé
      🚧 En cours
      v1.2.0
    
    
      Golden/Silver Tickets
      ⏳ Planifiée
      v1.3.0
    
    
      Détection des ACLs dangereuses
      ⏳ Planifiée
      v1.3.0
    
    
      Intégration avec BloodHound
      ✅ Terminée
      v1.1.0
    
  



### 🤝 Contribuer
Les contributions sont les bienvenues !

### 📄 Licence
Ce projet est sous licence MIT – voir le fichier LICENSE pour plus de détails.

## 📬 Contact
Pour toute question ou suggestion, contacte-moi via :

GitHub : @Fr3nch4Sec
Site Web : fr3nch4sec.github.io

⭐ Si ce projet t'est utile, n'hésite pas à le star sur GitHub !

---
