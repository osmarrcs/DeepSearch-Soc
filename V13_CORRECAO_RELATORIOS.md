# DeepSearch SOC v13 — padronização e diagnóstico dos boletins

Esta correção altera somente o gerador de boletim individual por CVE.

## Problemas corrigidos

1. O rótulo da tecnologia vinha da categoria usada na varredura. Uma CVE podia
   aparecer como "Windows" mesmo pertencendo a um produto de terceiro executado
   em Windows. Agora o produto é identificado por CNA/CVE Program e CPE/NVD.
2. O HTML da aplicação usava um modelo antigo diferente do notebook Colab.
   Agora o boletim segue sempre as seções:
   - Resumo executivo
   - Detalhes técnicos
   - Correção e monitoramento
   - Lacunas
   - Fontes usadas pela análise
   - Bases oficiais
3. Foi incluído o campo "Evidências" separado de "Exploração".
4. A resposta do Gemini agora usa Structured Output com JSON Schema.
5. O prompt diferencia:
   - CISA KEV de PoC público;
   - EPSS de confirmação de exploração;
   - IOCs reais de portas, usuários padrão, caminhos e configurações.
6. A tela mostra o estado de cada fonte consultada:
   NVD, CVE/MITRE, CISA KEV, EPSS, advisories e Gemini.
7. O fallback mudou para gemini-3.5-flash quando o modelo principal não estiver
   disponível.

## Arquivos alterados

- artifacts/api-server/src/lib/threat-intelligence.ts
- artifacts/api-server/src/routes/vulnerabilities.ts
- artifacts/cve-dashboard/src/pages/Boletim.tsx

## Implantação

1. Extraia o ZIP.
2. Copie as pastas `artifacts` para a raiz do repositório local.
3. Confirme a substituição dos três arquivos.
4. Commit: `v13.0.0 - padroniza boletins e diagnóstico das fontes`
5. Push origin.
6. Aguarde o deploy da API.
7. No serviço web do Render, use `Clear build cache & deploy`.

Não é necessário criar novas variáveis. Permanecem:

- NVD_API_KEY
- GEMINI_API_KEY
- GEMINI_MODEL (opcional)

## Verificação

Abra `/api/healthz/integrations` e confirme:

- `structuredOutput: true`
- `reportTemplate: colab-standard-v13`

Ao gerar um boletim, a tela exibirá cartões de status para cada fonte.
