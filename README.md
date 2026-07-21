# adhunt

**Énumération & pentest Active Directory de A à Z — en une seule commande.**

`adhunt.py` déroule automatiquement les 6 phases d'un pentest AD : découverte réseau → énumération non-authentifiée → attaque de mot de passe → énumération authentifiée → escalade/latéral → rapport. Il **pilote les vrais outils** (netexec, impacket, certipy, kerbrute, bloodhound-python, hashcat) quand ils sont présents, avec des **fallbacks 100 % Python** sinon. Il est **conscient du lockout**, sépare la lecture seule (`--safe`) des actions offensives (`--yes`), et **boucle** automatiquement : chaque nouveau credential trouvé/cracké relance l'énumération jusqu'au Domain Admin.

> ⚠️ **Usage AUTORISÉ uniquement** : pentest sous mandat, red team, CTF, lab. Reste STRICTEMENT dans le scope de ton engagement. Tu es responsable de ton usage.

---

## Table des matières
- [Ce que fait l'outil](#ce-que-fait-loutil)
- [La chaîne d'attaque (A → Z)](#la-chaîne-dattaque-a--z)
- [Les 6 phases en détail](#les-6-phases-en-détail)
- [Ce que l'outil combine](#ce-que-loutil-combine)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Options](#options)
- [Sorties (loot/)](#sorties-loot)
- [Sécurité & garde-fous](#sécurité--garde-fous)
- [Statut & limites](#statut--limites)

---

## Ce que fait l'outil

| | |
|---|---|
| **Une commande** | `python adhunt.py <cible> -d <domaine> -u <user> -p <pass> --all` |
| **6 phases enchaînées** | découverte → non-auth → spray → auth → escalade → rapport |
| **Auto-boucle** | nouveau cred (cracké / shadow / RBCD / PKINIT / gMSA) → re-enum → jusqu'au DA |
| **Pilote + fallback** | utilise nxc/impacket/certipy… si présents, sinon Python pur |
| **Lockout-aware** | lit la password policy et bride le spray pour **ne jamais locker un compte** |
| **Sûr par défaut** | `--safe` = lecture seule ; les actions offensives exigent `--yes` |
| **Rapport** | `report.md` priorisé par sévérité + `report.json` + `loot/` |

---

## La chaîne d'attaque (A → Z)

```
Découverte réseau (scan ports AD, repère les DC, SMB signing, clock skew)
      │
      ▼
Users valides (RID cycling, kerbrute) ──► AS-REP roasting ──┐
      │                                                     │
      ▼                                                     ▼
Password spray (lockout-aware) ─────────────────────► CRACK (hashcat/john)
      │                                                     │
      ▼                                                     ▼
  1er compte  ──► Dump LDAP + Kerberoast + ACL/DACL + LAPS + gMSA + shares + trusts
      │                                                     │
      ▼                                                     ▼
  ACL abusable ──► Shadow Credentials / RBCD / Targeted Kerberoast ──► HASH
      │                                                     │
      ▼                                                     ▼
  ADCS ESC ──► certipy req ──► PKINIT ──► HASH ────────► (réinjecté dans la boucle)
      │
      ▼
  Admin local (Pwn3d) ──► RCE (wmiexec) / secretsdump
      │
      ▼
  DCSync (secretsdump -just-dc) ──► NTDS ──► hash krbtgt ──► GOLDEN TICKET
```

Chaque hash/credential obtenu est **réinjecté** : avec `--loop`, l'outil relance l'énumération authentifiée avec le nouvel accès, jusqu'à épuisement des chemins.

---

## Les 6 phases en détail

### Phase 0 — Découverte (réseau, sans creds)
- Scan des ports AD (445 SMB, 389/636 LDAP, 88 Kerberos, 135 RPC, 53 DNS, 5985 WinRM, 1433 MSSQL, 3268 GC, 9389 ADWS…)
- **Détection automatique des Domain Controllers**
- **Sonde SMB2 pur-python** (zéro dépendance) : `signing requis ?` (→ surface de relais NTLM), dialecte, **clock skew Kerberos**
- rootDSE LDAP anonyme (domaine, forêt, naming contexts) + null session (OS, hostname)

### Phase 1 — Énumération non-authentifiée
- **Password policy** (récupérée AVANT tout spray → seuil de lockout)
- Null session SMB (shares/users/groups), **RID cycling**, LDAP anonyme
- **kerbrute** (énumération d'utilisateurs sans lockout), fallback **rpcclient**
- **AS-REP roasting** (comptes sans pré-auth → hash crackable sans creds)
- Surface notée : **relais NTLM** (signing off), **LLMNR/NBT-NS poisoning** (Responder), coercition

### Phase 2 — Attaque de mot de passe
- **Password spraying lockout-aware** : bride le nombre d'essais sous le seuil, throttle
- Wordlist auto (saison+année, nom de société, mots de passe communs)
- Les creds valides → réinjectés en Phase 3

### Phase 3 — Énumération authentifiée (le cœur)
- **Dump LDAP** (pagination complète) : users, computers, groupes, OU, GPO
  - Kerberoastable (SPN), AS-REP roastable, adminCount, flags UAC, délégations, **mots de passe dans les descriptions**
- **Scan ACL/DACL** (mini-BloodHound autonome) : GenericAll / WriteDACL / WriteOwner / ForceChangePassword / DCSync / AddMember — filtre les comptes privilégiés
- **Kerberoasting** + AS-REP (vue authentifiée)
- **GPP cpassword** (SYSVOL), **LAPS** (ms-Mcs-AdmPwd lisible), **gMSA** (msDS-ManagedPassword → hash NT)
- **ADCS** (certipy `-json`) : templates vulnérables ESC1→ESC16
- **Délégations** (unconstrained / constrained / RBCD), **trusts** (SID-history child→parent)
- **MSSQL** (sysadmin → xp_cmdshell, links cross-forest, vol NetNTLM)
- **Shares** : énumération authentifiée **+ spidering** des fichiers sensibles (`.config`, `.ps1`, `unattend.xml`, `.kdbx`…)
- **BloodHound** (collecte + analyse du zip : DCSync, délégation non contrainte, high-value)
- **Auto-crack** (hashcat/john) des hashes AS-REP/Kerberoast → creds réinjectés

### Phase 4 — Escalade & latéral (exploitation active, `--yes`)
- **Exploitation des ACL** : `GenericAll` sur un user → **Shadow Credentials** + **Targeted Kerberoast** ; `GenericWrite` sur une machine → **RBCD**
- **PKINIT** : `certipy req` (ESC1) → `certipy auth` → hash NT
- **Cartographie** des creds sur tous les hôtes (admin local ?) → **RCE** (wmiexec) + commande shell (evil-winrm)
- **DCSync** (`secretsdump -just-dc`) → NTDS → **extraction krbtgt → Golden Ticket**
- **Coercition + relais NTLM** (PetitPotam/Coercer → ntlmrelayx) avec `--relay`

### Phase 5 — Rapport
- `report.md` priorisé par sévérité (CRIT/HIGH/MED/INFO), comptes remarquables, creds, hashes à cracker, commandes prêtes
- `report.json` (état complet) + `loot/` (hashes, tickets, fichiers) + `audit.log` horodaté

---

## Ce que l'outil combine

adhunt **n'est pas** une réimplémentation : il **orchestre** les références de l'écosystème, avec un fallback Python pur quand elles manquent.

| Domaine | Outils pilotés | Fallback pur-python |
|---|---|---|
| Scan / DC | (scan natif) | ✅ sockets threadés |
| SMB signing / clock skew | — | ✅ **sonde SMB2 maison** |
| Enum SMB/RPC | netexec (nxc), enum4linux-ng, rpcclient | partiel |
| LDAP | ldap3 | ✅ dump + ACL + LAPS + trusts |
| Users / Kerberos | kerbrute, impacket (GetNPUsers, GetUserSPNs) | — |
| Password attacks | netexec, hashcat / john | — |
| BloodHound | bloodhound-python (+ analyse zip) | ✅ analyse JSON |
| ADCS | certipy (`-json`) | — |
| Shadow creds / PKINIT | certipy | — |
| RBCD | impacket (addcomputer, rbcd, getST) | commandes générées |
| Delegation / DCSync | impacket (findDelegation, secretsdump) | ✅ détection via LDAP |
| Coercion / relais | PetitPotam, Coercer, ntlmrelayx | — |
| Exécution | netexec (`-x`), wmiexec, evil-winrm | — |

> Quand un outil manque, adhunt **génère la commande prête à copier** — rien n'est perdu.

---

## Installation

```bash
git clone https://github.com/Rachkpt/AD_P3n7e5t3.git
cd AD_P3n7e5t3

# Fallbacks LDAP / pass-the-hash (recommandé, débloque le dump LDAP + ACL) :
pip install ldap3 impacket

# Outils externes : déjà présents sur Kali / Exegol. Sinon :
#   netexec (nxc), impacket, certipy-ad, kerbrute, bloodhound-python, hashcat
```

Python 3.8+. Fonctionne sous Linux (recommandé) et Windows. **La puissance maximale s'obtient sur Kali/Exegol** où tous les outils externes sont là.

### Wordlists incluses
Le dossier **`wordlists/`** contient `userlist.txt` + `passwordlist.txt` (utiles pour kerbrute / spray, ex. THM *Attacktive Directory*) :
```bash
# quand le null/RID est bloqué, on seed la phase 1 avec une userlist :
python adhunt.py <IP> -d <domaine> --anon --userlist wordlists/userlist.txt
```

---

## Utilisation

```bash
# Découverte d'un subnet (repère les DC, signing, clock skew)
python adhunt.py 10.10.10.0/24

# Cible unique + énumération anonyme
python adhunt.py 10.10.10.10 -d corp.local --anon

# Pipeline complet authentifié (mot de passe)
python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Ete2024!' --all --loop

# Full-auto CTF : exploite tout, boucle jusqu'au DA
python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Ete2024!' \
    --all --loop --yes --wordlist /usr/share/wordlists/rockyou.txt

# Pass-the-hash, lecture seule (rapport client sans action offensive)
python adhunt.py 10.10.10.10 -d corp.local -u jdoe -H <lm:nt> --all --safe
```

---

## Options

| Option | Rôle |
|---|---|
| `target` | IP, CIDR, hostname ou fichier de cibles |
| `-d, --domain` | Domaine AD (auto-détecté sinon) |
| `-u/-p` · `-H` · `-k` | User+pass · hash NTLM (pass-the-hash) · Kerberos |
| `--anon` | Énumération non-authentifiée (Phase 1) |
| `--spray` | Password spraying (Phase 2) |
| `--all` | Toutes les phases applicables |
| `--loop` | Re-enum auth à chaque nouveau cred (jusqu'au DA) |
| `--safe` | **Lecture seule** : aucune action offensive |
| `--yes` | Confirme les actions actives (DCSync, RBCD, relais, ADCS req, RCE) |
| `--relay` | Coercition + ntlmrelayx (avec `--yes` + `--lhost`) |
| `--wordlist` | Wordlist pour le crack auto (rockyou par défaut si présent) |
| `-o, --loot` | Dossier de sortie (défaut `loot/`) |

---

## Sorties (loot/)

```
loot/<domaine>/
├── report.md            # rapport priorisé (à lire en premier)
├── report.json          # état complet (machine-readable)
├── audit.log            # journal horodaté de toutes les actions
├── users.txt            # utilisateurs énumérés
├── valid_creds.txt      # creds trouvées (spray/crack)
├── cracked.txt          # hashes cassés
├── asrep.hashes         # AS-REP (hashcat -m 18200)
├── kerberoast.hashes    # Kerberoast (hashcat -m 13100)
├── sensitive_files.txt  # fichiers sensibles trouvés sur les shares
├── domain_ntds.ntds     # dump NTDS (si DCSync)
└── bh/                  # collecte BloodHound (zip)
```

> `loot/` est **exclu du dépôt** (`.gitignore`) car il contient des données sensibles.

---

## Sécurité & garde-fous

- **Bannière d'autorisation** + rappel de scope à chaque lancement
- **Lockout-aware** : lit la policy et bride le spray sous le seuil (ne locke pas les comptes)
- **`--safe`** = lecture seule stricte ; **`--yes`** requis pour toute action offensive (DCSync, RBCD, relais, RCE, req ADCS)
- Les actions destructives (reset de mot de passe via ForceChangePassword) ne sont **jamais automatiques** — commande générée uniquement
- **`audit.log`** horodaté pour la traçabilité de l'engagement

---

## Statut & limites

- **Phase 0** (scan + sonde SMB2) : validée en conditions réelles.
- **Phases 1→5** : la logique d'orchestration compile et se déroule de bout en bout ; les briques de parsing sont testées en isolé. **Les attaques réelles doivent être validées contre un DC** (lab **GOAD** ou box HTB AD).
- Les formats de sortie de certains outils (surtout netexec) varient selon les versions — la version de nxc est loggée pour diagnostiquer rapidement un parsing qui ne matche pas.

Contributions / retours de lab bienvenus.

---

*by 12akHack — outil de sécurité offensive. À utiliser uniquement sur des systèmes que tu es explicitement autorisé à tester.*
