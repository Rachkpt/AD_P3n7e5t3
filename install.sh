#!/usr/bin/env bash
# =====================================================================
# install.sh - installe adhunt en commande globale "adhunt"
# Kali / Debian / Ubuntu / n'importe quel Linux Debian-like.
# Apres ca : tu tapes juste  ->  adhunt <IP_du_DC> -d <domaine> ...
# =====================================================================
set -e
G='\033[92m'; Y='\033[93m'; R='\033[91m'; GR='\033[90m'; X='\033[0m'
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/adhunt.py"

echo -e "${G}[*] Installation d'adhunt...${X}"
[ -f "$SRC" ] || { echo -e "${R}[!] adhunt.py introuvable a cote de install.sh${X}"; exit 1; }

# 1) fin de lignes LF (au cas ou le fichier arrive en CRLF depuis Windows)
if head -1 "$SRC" | grep -q $'\r'; then
  echo -e "${GR}[i] Conversion CRLF -> LF (shebang)...${X}"
  sed -i 's/\r$//' "$SRC"
fi
chmod +x "$SRC"

# 2) dependances python (optionnelles mais recommandees : dump LDAP + PtH)
if command -v pip3 >/dev/null 2>&1; then
  echo -e "${GR}[i] Dependances python (ldap3, impacket)...${X}"
  pip3 install --quiet ldap3 impacket 2>/dev/null \
    || pip3 install --quiet --break-system-packages ldap3 impacket 2>/dev/null \
    || echo -e "${Y}[i] pip a echoue -> installe 'ldap3 impacket' a la main si besoin.${X}"
fi

# 3) choisit un dossier bin sur le PATH (system si possible, sinon ~/.local/bin)
SUDO=""
if [ -w /usr/local/bin ]; then
  BIN=/usr/local/bin
elif command -v sudo >/dev/null 2>&1; then
  BIN=/usr/local/bin; SUDO=sudo
else
  BIN="$HOME/.local/bin"; mkdir -p "$BIN"
fi

# 4) symlink -> 'git pull' met a jour la commande automatiquement
$SUDO ln -sf "$SRC" "$BIN/adhunt"
echo -e "${G}[+] Installe : ${BIN}/adhunt  ->  ${SRC}${X}"

# 5) verifie que BIN est bien dans le PATH
case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) echo -e "${Y}[i] Ajoute $BIN a ton PATH :${X}"
     echo -e "${GR}    echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${X}";;
esac

echo -e "${G}[+] Termine !${X} Lance simplement :"
echo -e "    ${G}adhunt <IP_du_DC> -d <domaine> -u <user> -p <pass>${X}"
echo -e "${GR}    Mise a jour  : cd $HERE && git pull   (symlink -> instantane, rien a refaire)${X}"
echo -e "${GR}    Desinstaller : ${SUDO} rm \$(command -v adhunt)${X}"
