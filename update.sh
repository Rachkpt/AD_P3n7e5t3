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
if PULL_OUT="$(git pull --ff-only 2>&1)"; then
  echo -e "${G}[+] Code a jour.${X}"
else
  echo -e "${Y}[!] git pull bloque :${X}"
  echo "$PULL_OUT" | sed 's/^/    /'
  echo -e "${GR}    Modifs locales ? Force la version du depot (tu perds tes modifs locales) :${X}"
  echo -e "${GR}       git fetch origin && git reset --hard origin/main && ./update.sh${X}"
  exit 1
fi

# 2) re-lance l'installeur : idempotent, remet le lien + installe toute NOUVELLE dep
chmod +x install.sh 2>/dev/null || true
bash install.sh

echo -e "${G}[+] adhunt est a jour et pret.${X}"
