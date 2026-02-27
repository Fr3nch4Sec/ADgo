# ADgo - Active Directory Tooling in Go

ADgo est un outil en ligne de commande pour effectuer des opérations de pentest et de CTF sur Active Directory.

## Installation

1. Clone le dépôt :
   ```bash
   git clone https://github.com/Fr3nch4Sec/adgo.git
   cd adgo
   go build -o adgo ./cmd/adgo


## Commandes Disponibles

| Commande                     | Description                                      |
|------------------------------|--------------------------------------------------|
| `adgo kerberoast`            | Effectue une attaque Kerberoasting.              |
| `adgo winrm exec`            | Exécute une commande via WinRM.                  |
| `adgo wmi query`             | Interroge des informations WMI.                  |
| `adgo rpc enumerate`         | Énumère les services RPC.                        |
| `adgo goldenticket`          | Crée un Golden Ticket.                           |
| `adgo silverticket`          | Crée un Silver Ticket.                           |
| `adgo pth`                   | Effectue une attaque Pass-the-Hash.              |
