# Deploy do DeepSearch SOC v12 — GitHub, Supabase e Render

Execute na ordem abaixo.

## 1. Substituir os arquivos no repositório local

1. Extraia o ZIP desta versão.
2. No GitHub Desktop, abra o repositório `DeepSearch-Soc`.
3. Use **Repository → Show in Explorer**.
4. Copie o conteúdo do ZIP para essa pasta, substituindo os arquivos existentes.
5. Não apague a pasta oculta `.git`.
6. Confirme que `artifacts`, `lib`, `render.yaml` e `package.json` estão diretamente na raiz.
7. Faça `Commit to main` e depois `Push origin`.

## 2. Sincronizar o Blueprint

Como os serviços estão marcados como **Blueprint managed**, alterações em `render.yaml` precisam ser sincronizadas pelo Blueprint.

1. No Render, abra o Blueprint do projeto.
2. Use a opção de sincronizar/aplicar a versão mais recente do `render.yaml`.
3. Aguarde a atualização dos serviços `deepsearch-soc-prod-api` e `deepsearch-soc-prod-web`.

As variáveis declaradas com `sync: false` mantêm o valor fora do Git e devem ser preenchidas no painel.

## 3. Variáveis da API

No serviço `deepsearch-soc-prod-api`, confirme:

```text
DATABASE_URL
CORS_ORIGIN
NVD_API_KEY
GEMINI_API_KEY
REDHAT_JFPE_TO
REDHAT_TRF5_TO
REDHAT_REPORT_CC
MICROSOFT_REPORT_TO
MICROSOFT_REPORT_CC
```

Valores fixos fornecidos pelo Blueprint:

```text
GEMINI_MODEL=gemini-3.6-flash
GEMINI_FALLBACK_MODEL=gemini-3.5-flash-lite
SCAN_DAYS=3
NVD_RESULTS_PER_TECH=10
SCAN_TECH_CONCURRENCY=4
```

### NVD_API_KEY

Cole somente a chave, sem aspas. Essa variável é a principal melhoria de velocidade quando várias tecnologias são selecionadas.

### GEMINI_API_KEY

Cole somente a chave. O Gemini não participa da varredura; ele é utilizado apenas ao gerar o boletim técnico por CVE.

### Destinatários

Use listas separadas por vírgula. Exemplo fictício:

```text
REDHAT_JFPE_TO=analista1@empresa.com,analista2@empresa.com
REDHAT_TRF5_TO=atendimento@empresa.com
REDHAT_REPORT_CC=soc@empresa.com
MICROSOFT_REPORT_TO=infra@empresa.com
MICROSOFT_REPORT_CC=soc@empresa.com
```

## 4. Variável do frontend

No serviço `deepsearch-soc-prod-web`:

```text
VITE_API_URL=https://deepsearch-soc-prod-api.onrender.com
```

Não acrescente `/api` e não coloque barra no final.

Depois de alterar `VITE_API_URL`, faça novo build do frontend com limpeza do cache.

## 5. Conexão Supabase

Use a URI do Transaction Pooler, porta `6543`:

```text
postgresql://postgres.PROJECT_REF:SENHA@HOST_POOLER.supabase.com:6543/postgres
```

O código remove parâmetros SSL conflitantes da URI e configura TLS no driver PostgreSQL.

## 6. Conferir o deploy da API

Os logs esperados são:

```text
[db] connection established
[db] bootstrap complete
Server listening
```

Teste:

```text
/api/healthz
/api/healthz/db
/api/healthz/integrations
/api/stats
```

`/api/healthz/integrations` mostra apenas se as chaves foram configuradas; nunca exibe os valores.

## 7. Testar a varredura

1. Abra **Varredura**.
2. Selecione data inicial e final.
3. Deixe **NVD + CISA KEV** marcadas.
4. Selecione uma ou mais tecnologias.
5. Inicie e acompanhe em **Histórico**.

Se aparecer o aviso `NVD_API_KEY não configurada`, volte às variáveis da API e cadastre a chave.

## 8. Testar os relatórios

### Boletim por CVE

1. Faça uma varredura.
2. Abra **Boletim por CVE**.
3. Selecione a vulnerabilidade.
4. Clique em **Gerar boletim**.

### Red Hat

1. Abra **Red Hat**.
2. Selecione o período.
3. Gere o relatório.
4. Copie ou baixe o HTML.

### Patch Tuesday

1. Abra **Patch Tuesday**.
2. Selecione o mês ou intervalo.
3. Gere o relatório.
4. Copie ou baixe o HTML.

As integrações Red Hat Security Data, MSRC/CVRF, CISA KEV, CVE/MITRE e EPSS não exigem variáveis adicionais nesta implementação.
