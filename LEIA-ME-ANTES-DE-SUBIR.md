# PATCH V12 — SOMENTE ARQUIVOS NOVOS E ALTERADOS

Este pacote contém menos de 100 arquivos e foi preparado para evitar o limite
do upload pelo navegador do GitHub.

## Forma recomendada

1. Abra o repositório local pelo GitHub Desktop.
2. Use Repository > Show in Explorer.
3. Extraia este ZIP.
4. Copie o CONTEÚDO extraído para a raiz do repositório.
5. Confirme a substituição dos arquivos.
6. No GitHub Desktop, verifique que aparecem arquivos novos e modificados.
7. Commit: `v12.0.0 - relatórios e otimização do scanner`
8. Push origin.

## Verificação no GitHub antes do Render

Confirme que estes arquivos existem na branch main:

- artifacts/cve-dashboard/src/pages/RedHatReport.tsx
- artifacts/cve-dashboard/src/pages/MicrosoftPatchTuesday.tsx
- artifacts/api-server/src/routes/reports.ts
- artifacts/api-server/src/lib/threat-intelligence.ts

E confirme que `artifacts/cve-dashboard/src/App.tsx` contém as rotas:

- /relatorios/red-hat
- /relatorios/patch-tuesday

Somente depois disso faça o deploy no Render.
