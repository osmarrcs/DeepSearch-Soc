# DEPLOY — DeepSearch-Soc (Supabase + Render)

Zero-to-production em ~15 minutos. Segue **na ordem**.

---

## PASSO 1 — Criar banco na Supabase (5 min, grátis)

1. Vai em https://supabase.com/dashboard/projects → **New project**.
2. Preenche:
   - **Name:** `deepsearch-soc-prod`
   - **Database password:** clica em **Generate a password** e **COPIA E SALVA** (aparece uma vez só)
   - **Region:** a mais perto de você (ex: `South America (São Paulo)`)
   - **Plan:** Free
3. Aguarda ~2 min o projeto provisionar.
4. Menu esquerdo → **Project Settings** (engrenagem) → **Database**.
5. Rola até **Connection string** → aba **Transaction pooler** (porta **6543**).
6. Copia a string. Vai estar tipo:
   ```
   postgresql://postgres.abcdefghijklmno:[YOUR-PASSWORD]@aws-0-sa-east-1.pooler.supabase.com:6543/postgres
   ```
7. **Substitui `[YOUR-PASSWORD]`** pela senha do passo 2 e **adiciona `?sslmode=require` no final**:
   ```
   postgresql://postgres.abcdefghijklmno:MinhaSenh4Aqui@aws-0-sa-east-1.pooler.supabase.com:6543/postgres?sslmode=require
   ```
8. **Guarda essa URL** — vai colar no Render no Passo 4. Chamamos ela de `DATABASE_URL`.

> ⚠️ Usa o **Transaction pooler (6543)**, NÃO o Direct connection (5432). Render + pooler = sem estouro de conexão.

---

## PASSO 2 — Rodar as migrations (2 min)

Precisa criar as tabelas no banco. Faz local **uma vez**:

```bash
# clona o repo existente
git clone https://github.com/osmarrcs/DeepSearch-Soc.git
cd DeepSearch-Soc

# instala
corepack enable
pnpm install

# roda migration apontando pro Supabase
export DATABASE_URL="postgresql://postgres.abcdefghijklmno:MinhaSenh4Aqui@aws-0-sa-east-1.pooler.supabase.com:6543/postgres?sslmode=require"
pnpm --filter @workspace/db push
```

Confirma quando pedir. Depois vai na Supabase → **Table Editor** e confere se as tabelas `scans` e `vulnerabilities` apareceram.

---

## PASSO 3 — Subir código no GitHub (3 min)

Repo já existe em: `https://github.com/osmarrcs/DeepSearch-Soc`

Se você está enviando o código pela primeira vez (ou sobrescrevendo):
```bash
# dentro da pasta DeepSearch-Soc
git init
git add .
git commit -m "initial commit" || true
git branch -M main
git remote add origin https://github.com/osmarrcs/DeepSearch-Soc.git
# se o repo remoto já tiver histórico e você quiser forçar o conteúdo novo:
git push -u origin main --force-with-lease
```

> ⚠️ Use `--force-with-lease` só se o repo estiver vazio ou você quiser substituir o conteúdo atual. Se quiser preservar histórico, faça merge/pull antes.

---

## PASSO 4 — Deploy no Render (5 min)

### 4.1 Cria os serviços via Blueprint

1. https://dashboard.render.com/select-repo?type=blueprint
2. Conecta o repo `DeepSearch-Soc`.
3. Render lê o `render.yaml` e mostra 2 serviços:
   - `deepsearch-soc-prod-api` (Web Service)
   - `deepsearch-soc-prod-web` (Static Site)
4. Clica **Apply**.

### 4.2 Preenche as env vars

Ele vai pedir 3 valores:

| Serviço | Variável | Valor |
|---|---|---|
| `deepsearch-soc-prod-api` | `DATABASE_URL` | a URL do Passo 1 (com senha e `?sslmode=require`) |
| `deepsearch-soc-prod-api` | `CORS_ORIGIN` | **deixa em branco por enquanto** — volta depois |
| `deepsearch-soc-prod-web` | `VITE_API_URL` | **deixa em branco por enquanto** — volta depois |

Clica **Apply** de novo. Render começa o build (leva ~5 min).

### 4.3 Descobre as URLs finais

Quando os dois serviços ficarem **Live**, o Render mostra as URLs:
- API: `https://deepsearch-soc-prod-api.onrender.com` (ou `-abcd` no fim se tiver conflito)
- Web: `https://deepsearch-soc-prod-web.onrender.com`

### 4.4 Preenche as URLs cruzadas

Agora que você tem as URLs, volta e completa:

**deepsearch-soc-prod-api** → Environment → edita:
- `CORS_ORIGIN` = `https://deepsearch-soc-prod-web.onrender.com` (URL do web, **sem barra no final**)

**deepsearch-soc-prod-web** → Environment → edita:
- `VITE_API_URL` = `https://deepsearch-soc-prod-api.onrender.com` (URL da api, **sem barra no final**)

Cada edição dispara um redeploy. Espera ficar **Live**.

---

## PASSO 5 — Testar

1. Abre `https://deepsearch-soc-prod-api.onrender.com/api/healthz` → deve retornar `{"ok":true}`.
2. Abre `https://deepsearch-soc-prod-web.onrender.com` → dashboard carrega.
3. Vai em **Scanner** → seleciona uma tech → **Iniciar Varredura** → aparece toast verde e vira status "em_andamento".

Se qualquer um falhar, vai pro **Troubleshooting** embaixo.

> Importante: nesta versão, o `render.yaml` roda `pnpm --filter @workspace/db db:bootstrap` antes de iniciar a API. Isso corrige automaticamente o schema do banco em produção, inclusive o campo `scans.technologies` que causava 500 no `POST /api/scans`.

---

## Dev local

```bash
# .env na raiz OU exporta manualmente
export DATABASE_URL="postgresql://...pooler.supabase.com:6543/postgres?sslmode=require"

# terminal 1
pnpm --filter @workspace/api-server dev

# terminal 2
pnpm --filter @workspace/cve-dashboard dev
```

Sem `VITE_API_URL` em dev, o Vite proxya `/api` pra `localhost:3000`.

---

## Troubleshooting

| Sintoma | Causa | Fix |
|---|---|---|
| Render build: `pnpm: not found` | `corepack` não ativou | já tá no `buildCommand`; se falhar, ativa Node 20+ no Render |
| `password authentication failed` | senha errada ou `[YOUR-PASSWORD]` não substituído | volta no Passo 1.7 |
| `self signed certificate` / `no pg_hba.conf entry` | faltou `?sslmode=require` na URL | adiciona no final da `DATABASE_URL` |
| `too many connections` | usou porta 5432 (direct) | troca pra `6543` (pooler) no Passo 1.5 |
| Dashboard chama API e dá CORS | `CORS_ORIGIN` errado ou com barra final | copia exato: `https://xxx.onrender.com` |
| Dashboard mostra tela em branco | `VITE_API_URL` não setado no build | seta no `deepsearch-soc-prod-web` e força redeploy (build-time var) |
| `drizzle-kit push` falha `__dirname is not defined` | versão antiga do arquivo | já corrigido nesse repo |
| `POST /api/scans` retorna 500 com `insert into "scans"` e `technologies` | banco antigo com tipo incompatível no campo `scans.technologies` | faça deploy desta versão; a API roda `db:bootstrap` no start e converte o campo sem apagar dados |
| API dorme depois de 15min | Render free spin-down | normal; primeira request depois demora ~30s |

---

## Rotacionar senha do banco (se vazar)

1. Supabase → Settings → Database → **Reset database password**
2. Copia nova URL com nova senha
3. Render → `deepsearch-soc-prod-api` → Environment → atualiza `DATABASE_URL` → salva (redeploy automático)
