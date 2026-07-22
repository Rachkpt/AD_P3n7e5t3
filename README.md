# adhunt

**Énumération Active Directory avec un tableau de bord vivant — tu fournis l'IP du DC, il énumère et affiche ce qu'il trouve.**

**Pas de scan nmap dans l'outil** : tu as déjà scanné, tu donnes l'IP du DC. `adhunt.py` confirme les services AD (LDAP/SMB/Kerberos/DNS), puis **énumère** et remplit un **tableau de bord qui se redessine au fur et à mesure** : `utilisateurs → shares/fichiers sensibles → hashes → mots de passe crackés → credentials`. Il **crack automatiquement** les hashes AS-REP/Kerberoast (hashcat → John) et réinjecte les mots de passe. Il **pilote les vrais outils** (netexec, impacket, certipy, kerbrute, bloodhound-python, hashcat) avec **fallback 100 % Python** sinon.

**L'écran ne montre que les trouvailles** — la progression et les erreurs vont dans `loot/<domaine>/debug.log` (option `--verbose` pour tout voir). Par défaut il **n'attaque pas** : l'escalade offensive (DCSync, ADCS/ESC, RBCD/shadow, DACL, disk hunt) est **derrière `--exploit`**.

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
| **Une commande** | `python adhunt.py <IP_du_DC> -d <domaine> -u <user> -p <pass>` |
| **Pas de scan** | tu fournis l'IP du DC ; adhunt confirme juste les services (aucun nmap) |
| **Tableau de bord vivant** | users → shares → hashes → crack → creds, **se redessine quand il trouve** |
| **Écran propre** | affiche les trouvailles, **pas les erreurs** (→ `debug.log`, `--verbose` pour tout) |
| **Crack auto** | AS-REP/Kerberoast crackés (hashcat→John) et mots de passe réinjectés |
| **Sûr par défaut** | énumère seulement ; l'escalade offensive est derrière **`--exploit`** |
| **Rapport** | `report.md` priorisé par sévérité + `report.json` + `loot/` |

---

## La chaîne d'attaque (A → Z)

```
Recon : confirme les services AD sur l'IP fournie (pas de scan nmap)
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

### Recon — Confirmation des services (PAS de scan)
- **Aucun nmap** : tu as déjà scanné et tu donnes l'IP du DC. adhunt teste juste les ports AD connus pour **confirmer** que LDAP/SMB/Kerberos/DNS répondent.
- **Détection automatique des Domain Controllers**
- **Sonde SMB2 pur-python** (zéro dépendance) : `signing requis ?` (→ surface de relais NTLM), dialecte, **clock skew Kerberos**
- rootDSE LDAP anonyme (domaine, forêt, naming contexts) + null session (OS, hostname) → renseigne l'entête du tableau de bord

### Phase 1 — Énumération non-authentifiée
- **Password policy** (récupérée AVANT tout spray → seuil de lockout)
- Null session SMB (shares/users/groups), **RID cycling**, LDAP anonyme, **table des users confirmés**
- **kerbrute** (énumération d'utilisateurs sans lockout, seed via `--userlist`), fallback **rpcclient**
- **AS-REP roasting** + **Kerberoast via Guest** (foothold sans creds valides) → **auto-crack** (hashcat→John si pas de GPU)
- Surface notée : **relais NTLM** (signing off), **LLMNR/NBT-NS poisoning** (Responder), coercition

### Phase 2 — Attaque de mot de passe (opt-in : `--spray`)
- **Password spraying lockout-aware** : bride le nombre d'essais sous le seuil, throttle
- Wordlist auto (saison+année, **nom de société dérivé du domaine**, mots de passe communs) ou `--passwordlist`
- **Réutilisation de mot de passe** : rejoue les mdp crackés sur tous les users
- Les creds valides → réinjectés en Phase 3

### Phase 3 — Énumération authentifiée (le cœur)
- **Dump LDAP** (pagination complète) : users, computers, groupes, OU, GPO
  - Kerberoastable (SPN), AS-REP roastable, adminCount, flags UAC, délégations, **mots de passe dans les descriptions**
- **Scan ACL/DACL** (mini-BloodHound autonome) : GenericAll / WriteDACL / WriteOwner / ForceChangePassword / DCSync / AddMember — filtre les comptes privilégiés
- **Kerberoasting** + AS-REP (vue authentifiée)
- **GPP cpassword** (SYSVOL + `Get-GPPPassword.py`), **LAPS** (ms-Mcs-AdmPwd + `GetLAPSPassword.py`), **gMSA** (msDS-ManagedPassword → hash NT)
- **ADCS** (certipy `-json`) : templates vulnérables ESC1→ESC16
- **BadSuccessor** (2025) : détection dMSA (msDS-DelegatedManagedServiceAccount) → héritage de privilèges
- **Délégations** (unconstrained / constrained / RBCD), **trusts** (raiseChild / goldenPac child→parent, SID-history)
- **MSSQL** (sysadmin → xp_cmdshell, links cross-forest, vol NetNTLM)
- **Shares** : énum authentifiée **+ LOOT réel** (télécharge les fichiers sensibles, **décode le base64**, extrait les creds → réinjectées dans la boucle)
- **BloodHound** (collecte + analyse du zip : DCSync, délégation non contrainte, high-value)
- **Auto-crack** (hashcat → **fallback John si pas de GPU**) des hashes AS-REP/Kerberoast → creds réinjectés

### Phase 4 — Escalade & latéral (**seulement avec `--exploit`**)
- **Exploitation des ACL** : `GenericAll` sur un user → **Shadow Credentials** + **Targeted Kerberoast** ; `GenericWrite` sur une machine → **RBCD** ; `WriteDACL` sur le domaine → **dacledit** (auto-DCSync)
- **PKINIT** : `certipy req` (ESC1) → `certipy auth` → hash NT
- **Cartographie** des creds sur tous les hôtes (admin local ?) → **RCE** (wmiexec) + commande shell (evil-winrm)
- **DCSync** (`secretsdump -just-dc`) → NTDS → **extraction krbtgt → Golden Ticket**
- **Coercition + relais NTLM** (PetitPotam/Coercer → ntlmrelayx) avec `--relay`

### Phase 5 — Rapport
- `report.md` **priorisé par sévérité** (CRIT/HIGH/MED/INFO), comptes remarquables, creds, hashes à cracker, commandes prêtes — **findings dédupliqués**
- `report.json` (état complet) + `loot/` (hashes, tickets, fichiers) + `audit.log` horodaté
- **`[>] PROCHAINE COMMANDE`** : suggère la commande à lancer ensuite selon l'état (nouveau cred → `--all`, NTDS → evil-winrm…)

---

## Ce que l'outil combine

adhunt **n'est pas** une réimplémentation : il **orchestre** les références de l'écosystème, avec un fallback Python pur quand elles manquent.

| Domaine | Outils pilotés | Fallback pur-python |
|---|---|---|
| Confirmation services / DC | (pas de nmap) | ✅ sockets threadés (ports AD only) |
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

> Tu as **déjà fait ton nmap** → tu donnes l'IP du DC. adhunt ne scanne pas.

```bash
# Énum non-authentifiée (users, AS-REP + Kerberoast via Guest, crack auto)
python adhunt.py 10.10.10.10 -d corp.local

# Énum AUTHENTIFIÉE complète (LDAP, roast, GPP/LAPS/gMSA, fouille des shares, crack)
python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Ete2024!'

# Pass-the-hash
python adhunt.py 10.10.10.10 -d corp.local -u jdoe -H <nthash>

# + ESCALADE offensive (DCSync/ADCS/RBCD/DACL/disk) + boucle jusqu'au DA
python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Ete2024!' --exploit --loop

# Voir tout le détail à l'écran (sinon dans loot/<domaine>/debug.log)
python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Ete2024!' --verbose
```

---

## Options

| Option | Rôle |
|---|---|
| `target` | **IP du DC** (celle que ton nmap a trouvée), hostname ou fichier de cibles |
| `-d, --domain` | Domaine AD (auto-détecté sinon) |
| `-u/-p` · `-H` · `-k` | User+pass · hash NTLM (pass-the-hash) · Kerberos |
| `--exploit` | **Active l'escalade offensive** (DCSync, ADCS/ESC, RBCD/shadow, DACL, disk hunt). Sans ce flag : énum + roast + crack + affichage seulement |
| `--loop` | Re-enum auth à chaque nouveau cred (jusqu'au DA) — utile avec `--exploit` |
| `--spray` | Password spraying (opt-in, lockout-aware) |
| `--verbose` | Réaffiche à l'écran la progression + les erreurs (sinon dans `debug.log`) |
| `--safe` | **Lecture seule** : aucune action offensive même avec `--exploit` |
| `--relay` | Coercition + ntlmrelayx (avec `--exploit` + `--lhost`) |
| `--userlist` | Userlist pour seeder l'énum (ex: `wordlists/userlist.txt`) |
| `--wordlist` | Wordlist pour le crack auto (rockyou par défaut si présent) |
| `--passwordlist` | Wordlist pour le spray (défaut : liste intégrée adaptée au domaine) |
| `-o, --loot` | Dossier de sortie (défaut `loot/`) |

---

## Sorties (loot/)

```
loot/<domaine>/
├── report.md            # rapport priorisé (à lire en premier)
├── report.json          # état complet (machine-readable)
├── debug.log            # progression + erreurs (tout le détail que l'écran cache)
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

- **Recon** (confirmation services + sonde SMB2) et **tableau de bord vivant** : validés (rendu, filtre d'erreurs, redraw testés).
- **Énum → crack → escalade** : la logique compile et se déroule de bout en bout ; les briques de parsing sont testées en isolé. **Les attaques réelles doivent être validées contre un DC** (lab **GOAD** ou box HTB/THM AD).
- Les formats de sortie de certains outils (surtout netexec) varient selon les versions — la version de nxc est loggée pour diagnostiquer rapidement un parsing qui ne matche pas.

Contributions / retours de lab bienvenus.

---

*by 12akHack — outil de sécurité offensive. À utiliser uniquement sur des systèmes que tu es explicitement autorisé à tester.*
