# DEPLOY — Data-Extractor (Supabase + Render)

Guia rápido pra rodar do zero. **Banco:** Supabase (Postgres gerenciado, plano free — mais fácil que Neon pra começar). **Hospedagem:** Render (API como Web Service, dashboard como Static Site).

---

## 1. Criar o banco na Supabase (grátis)

1. Cria projeto em https://supabase.com → **New project**.
2. Anota a senha do Postgres (única vez que aparece).
3. Menu **Project Settings → Database → Connection string → URI** e escolhe a aba **Transaction pooler** (porta 6543). Copia a URL.
4. Adiciona `?sslmode=require` no final se ainda não tiver.

Vai ficar algo tipo:
```
postgres://postgres.xxxx:SUA_SENHA@aws-0-sa-east-1.pooler.supabase.com:6543/postgres?sslmode=require
```

> Prefira o **pooler** (6543), não a conexão direta (5432). O pooler aguenta melhor picos e não segura conexão ociosa — combina com o `max: 5` do pool no código.

---

## 2. Rodar as migrations

Localmente, com o repo clonado:

```bash
corepack enable
pnpm install
export DATABASE_URL="postgres://...pooler.supabase.com:6543/postgres?sslmode=require"
pnpm --filter @workspace/db push
```

Isso cria as tabelas `scans` e `vulnerabilities` na sua Supabase.

---

## 3. Deploy no Render

### Opção A — Blueprint (1 clique)
1. Sobe esse repo no GitHub.
2. No Render, **New → Blueprint** → aponta pro repo. O `render.yaml` cria os dois serviços.
3. Preenche as envs quando pedido:
   - **deepsearch-soc-api**
     - `DATABASE_URL` = URL da Supabase (passo 1)
     - `CORS_ORIGIN` = URL pública do dashboard (ex: `https://deepsearch-soc-web.onrender.com`)
   - **deepsearch-soc-web**
     - `VITE_API_URL` = URL pública da API (ex: `https://deepsearch-soc-api.onrender.com`)

### Opção B — Manual

**Web Service (API)**
- Root Directory: `.`
- Build: `corepack enable && pnpm install --frozen-lockfile && pnpm --filter @workspace/api-server... build`
- Start: `pnpm --filter @workspace/api-server start`
- Health Check Path: `/api/healthz`
- Env: `DATABASE_URL`, `CORS_ORIGIN`, `NODE_ENV=production`
- **NÃO** setar `PORT` — o Render injeta.

**Static Site (Dashboard)**
- Root Directory: `artifacts/cve-dashboard`
- Build: `corepack enable && pnpm install --frozen-lockfile --dir ../.. && pnpm --filter @workspace/cve-dashboard build`
- Publish Directory: `dist`
- Rewrite: `/*` → `/index.html` (200)
- Env (build-time): `VITE_API_URL`

---

## 4. Dev local

```bash
# terminal 1 — API
export DATABASE_URL="postgres://...supabase..."
pnpm --filter @workspace/api-server dev

# terminal 2 — Dashboard (proxya /api → localhost:3000 automaticamente)
pnpm --filter @workspace/cve-dashboard dev
```

Sem `VITE_API_URL` em dev, o dashboard usa caminhos relativos e o vite proxya `/api` pra `http://localhost:3000` (config em `vite.config.ts`).

---

## 5. Troubleshooting

| Sintoma | Causa | Fix |
|---|---|---|
| `Expected 3 parts in JWT` | rodou com anon key da Supabase, não a connection string | usa a **Database URI** (Settings → Database), não a API key |
| `self signed certificate` / `no pg_hba.conf entry` | SSL não ativado | garante `?sslmode=require` na URL e código atual do `lib/db/src/index.ts` |
| Front chama API e dá CORS | `CORS_ORIGIN` não bate com a origem do site | copia exatamente `https://...onrender.com` (sem barra final) |
| `drizzle-kit push` falha com `__dirname is not defined` | rodando versão antiga | já corrigido — `lib/db/drizzle.config.ts` usa `import.meta.url` |
| Scan trava em `em_andamento` para sempre | processo caiu no meio | reinicia o serviço; débito técnico conhecido (documentado no REVIEW.md) |

---

## 6. O que mudou nessa revisão

- **DB:** SSL + pool serverless-friendly (funciona com Supabase, Neon, Railway).
- **API:** PORT com fallback, shutdown gracioso, CORS por env, error handler global JSON.
- **Dashboard:** removidas dependências do Replit, `vite.config.ts` portátil, `VITE_API_URL` wire-up (`src/api-init.ts`), proxy `/api` em dev.
- **Infra:** `render.yaml` pronto pra Blueprint, sem arquivos `.replit`.

Detalhes técnicos no `REVIEW.md` do relatório original.
