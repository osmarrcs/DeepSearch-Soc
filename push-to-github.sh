#!/usr/bin/env bash
set -euo pipefail

# Script para subir/atualizar o código no repo existente:
# https://github.com/osmarrcs/DeepSearch-Soc
#
# Uso:
#   chmod +x push-to-github.sh
#   ./push-to-github.sh
#
# Requisitos: git, gh (GitHub CLI) autenticado.

REPO_URL="https://github.com/osmarrcs/DeepSearch-Soc.git"
REPO_NAME="DeepSearch-Soc"

echo "🚀 Preparando push para $REPO_URL"

# Verifica git
if ! command -v git &> /dev/null; then
  echo "❌ git não encontrado. Instale o git e tente novamente."
  exit 1
fi

# Verifica gh (opcional, só pra confirmar acesso)
if command -v gh &> /dev/null; then
  echo "✅ GitHub CLI encontrada"
  gh auth status || true
else
  echo "⚠️  GitHub CLI (gh) não encontrada. Continuando só com git..."
fi

# Inicializa repo se necessário
if [ ! -d .git ]; then
  echo "📁 Inicializando repositório git local..."
  git init
fi

# Configura remote
if git remote get-url origin &> /dev/null; then
  CURRENT_URL=$(git remote get-url origin)
  if [ "$CURRENT_URL" != "$REPO_URL" ]; then
    echo "🔄 Ajustando remote origin de $CURRENT_URL para $REPO_URL"
    git remote set-url origin "$REPO_URL"
  fi
else
  echo "➕ Adicionando remote origin"
  git remote add origin "$REPO_URL"
fi

# Garante branch main
git branch -M main

# Adiciona e commita
echo "📦 Criando commit..."
git add .
if git diff --cached --quiet; then
  echo "ℹ️  Nada de novo para commitar."
else
  git commit -m "update: DeepSearch-Soc deployment package" || true
fi

# Pergunta se quer forçar (caso o repo já tenha conteúdo)
echo ""
echo "⚠️  ATENÇÃO: o repo remoto pode já ter conteúdo."
read -p "Deseja forçar o push (--force-with-lease)? (s/N): " FORCE
if [[ "$FORCE" =~ ^[Ss]$ ]]; then
  echo "🔥 Enviando com --force-with-lease..."
  git push -u origin main --force-with-lease
else
  echo "📤 Enviando normalmente..."
  git push -u origin main
fi

echo ""
echo "✅ Pronto! Verifique em: https://github.com/osmarrcs/$REPO_NAME"
