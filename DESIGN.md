# adhunt — Enumeration Active Directory de A a Z

Orchestrateur d'enumeration/pentest AD pour engagements **autorises** (pentest interne, red team, CTF, labs). Philosophie identique a l'arsenal bunty : **Python pur qui pilote les vrais outils quand ils sont presents, fallback pur-python sinon**, sortie structuree (txt/json), conscient du lockout, un seul point d'entree.

> [!] Usage AUTORISE uniquement. Rester STRICTEMENT dans le scope de l'engagement.

---

## Principe
`adhunt.py <cible/DC>` enchaine automatiquement les phases. Chaque phase ecrit dans `loot/<domaine>/`. Les creds trouvees a une phase alimentent la suivante (harvest -> spray -> auth-enum -> roast -> escalation).

Modes : `--anon` (sans creds), `-u user -p pass` / `-H ntlmhash` (authentifie), `-k` (Kerberos/ticket), `--spray` (attaque de mot de passe), `--all` (tout).

---

## Les 6 phases (A -> Z)

### Phase 0 — DECOUVERTE (reseau, sans creds)
- Balayage du subnet : hote up + ports AD (445 SMB, 389/636 LDAP, 88 Kerberos, 135 RPC, 53 DNS, 5985 WinRM, 3389 RDP, 1433 MSSQL, 9389 ADWS, 464 kpasswd).
- Identification des **Domain Controllers** (LDAP+Kerberos+SMB).
- rootDSE via LDAP anonyme : nom de domaine, foret, naming contexts, niveau fonctionnel.
- Verif du **clock skew** (Kerberos casse si > 5 min) + auto-conseil `ntpdate`.
- Fingerprint SMB : version, **signing requis ?** (surface relais NTLM), SMBv1, null session.

### Phase 1 — ENUM NON-AUTHENTIFIEE (anonyme / null)
- **SMB null session** : shares, users, groups, password policy, RID cycling (SID brute -> users).
- **LDAP anonymous bind** : dump users/groupes si autorise.
- **Enum utilisateurs Kerberos** (kerbrute) : valider les usernames via AS-REQ (sans lockout).
- **AS-REP roasting** : comptes `DONT_REQ_PREAUTH` -> hash crackable SANS creds.
- Surface d'attaque notee : signing off (relais), **LLMNR/NBT-NS/mDNS** (Responder), **IPv6/mitm6**, coercion (PetitPotam/PrinterBug), anonymous LDAP/SMB/NFS.
- **Password policy** recuperee AVANT tout spray (seuil de lockout).

### Phase 2 — ATTAQUE DE MOT DE PASSE (obtenir des creds)
- Construction de la userlist (depuis phase 1) + wordlists (saison+annee, username=password, communs).
- **Password spraying** conscient du lockout (throttle, 1 essai/compte/fenetre, pause auto).
- AS-REP roast des users valides.
- Detection creds par defaut / faibles, comptes `PASSWD_NOTREQD`.

### Phase 3 — ENUM AUTHENTIFIEE (avec un compte low-priv)  ← le coeur
- **Dump LDAP complet** : users, groups, computers, OUs, GPOs, trusts, ACLs.
- Users : `description` (mots de passe planques dedans !), `pwdLastSet`, `lastLogon`, `adminCount`, flags UAC (disabled, no-preauth, pwd-never-expires, **trusted-for-delegation**), SPNs.
- **Kerberoasting** : comptes avec SPN -> hash service crackable.
- **AS-REP roasting** (vue authentifiee).
- Appartenances aux groupes sensibles (Domain/Enterprise Admins, DNSAdmins, Backup Operators, Account Operators...).
- Computers : OS, **LAPS** present ?, delegation (unconstrained / constrained / **RBCD**).
- **GPP cpassword** dans SYSVOL (Groups.xml -> mdp dechiffrable), scripts NETLOGON.
- **ADCS** (certipy) : templates vulnerables **ESC1 -> ESC14/16**, Web Enrollment (ESC8/NTLM relais).
- **Delegations** : unconstrained, constrained (+protocol transition), RBCD ; **MachineAccountQuota**.
- **Trusts** intra/inter-foret + direction (chemins cross-domaine).
- **BloodHound** : collecte (bloodhound-python) -> chemins d'attaque vers DA.
- **Spidering des shares** : fichiers sensibles (creds, .kdbx, web.config, unattend.xml, *.ps1).
- **MSSQL** : liens, `xp_cmdshell`, impersonation.
- **Analyse d'ACL** : GenericAll/GenericWrite/WriteDACL/WriteOwner/AddMember -> abus DACL.
- Droits **DCSync** (Replicating Directory Changes).

### Phase 4 — ESCALADE & LATERAL (analyse + quick wins)
- Cartographie creds -> ou elles ouvrent (nxc en masse : SMB/WinRM/MSSQL/RDP) + **admin local ?**.
- Priorisation : kerberoastable-crackable-admin, ESC ADCS, RBCD, delegation, DCSync.
- Chemins BloodHound « shortest path to Domain Admin ».
- (Si autorise) primitives : secretsdump (SAM/LSA/NTDS), extraction offline.

### Phase 5 — RAPPORT
- Rapport consolide : findings priorises, chemins d'attaque, creds cassees, quick wins, surface de relais/coercion.
- Sorties : `report.md` + `report.json` + `loot/` (hashes, tickets, fichiers).

---

## Outils pilotes (avec fallback pur-python)
netexec/nxc, impacket (GetNPUsers, GetUserSPNs, secretsdump, ntlmrelayx, findDelegation, lookupsid),
ldap3/ldapsearch, kerbrute, bloodhound-python, certipy, enum4linux-ng, nmap/naabu, hashcat/john.
Fallbacks : LDAP via `ldap3`, Kerberos via `impacket`, scan de ports natif, RID cycling natif.

## Garde-fous
- Banniere « autorise uniquement » + confirmation scope.
- **Lockout-aware** par defaut : lit la policy, throttle, s'arrete avant le seuil.
- `--safe` (lecture seule, pas de spray), `--yes` pour confirmer les actions actives.
- Journalise tout (audit) : horodatage, requetes, resultats.
