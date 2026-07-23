#!/usr/bin/env bash
# =====================================================================
# update.sh - met a jour adhunt (code + dependances + lien) en 1 commande.
# Usage :  ./update.sh
# =====================================================================
set -e
G='\033[92m'; Y='\033[93m'; R='\033[91m'; GR='\033[90m'; X='\033[0m'
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo -e "${G}[*] Mise a jour d'adhunt...${X}"

# 1) recupere la derniere version (fast-forward only = pas de merge surprise)
if git pull --ff-only 2>/tmp/adhunt_pull.err; then
  echo -e "${G}[+] Code a jour.${X}"
else
  echo -e "${Y}[!] git pull bloque (souvent des modifs locales dans le depot).${X}"
  echo -e "${GR}    -> mets tes modifs de cote puis reessaie :${X}"
  echo -e "${GR}       git stash && ./update.sh   (git stash pop pour les recuperer apres)${X}"
  cat /tmp/adhunt_pull.err 2>/dev/null | sed 's/^/    /'
  exit 1
fi

# 2) re-lance l'installeur : idempotent, remet le lien + installe toute NOUVELLE dep
chmod +x install.sh 2>/dev/null || true
bash install.sh

echo -e "${G}[+] adhunt est a jour et pret.${X}"
