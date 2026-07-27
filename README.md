# DeepSearch-Soc

Plataforma SOC (Security Operations Center) para **varredura, catalogação e monitoramento contínuo de CVEs** por stack tecnológica. Cadastre as tecnologias que sua empresa usa, dispare varreduras sob demanda e receba boletins consolidados das vulnerabilidades que realmente importam.

![stack](https://img.shields.io/badge/stack-Node%20%7C%20React%20%7C%20Postgres-informational)
![deploy](https://img.shields.io/badge/deploy-Render%20%2B%20Supabase-success)
![license](https://img.shields.io/badge/license-MIT-blue)

---

## ✨ Funcionalidades

- **Catálogo de tecnologias** — versionado por vendor/produto.
- **Varreduras sob demanda** — dispara pesquisa de CVEs para as tecnologias selecionadas.
- **Dashboard operacional** — visão de severidade (Critical / High / Medium / Low), tendências e KPIs.
- **Boletim** — resumo consolidado pronto para compartilhar com o time.
- **Feedback visual completo** — spinners, skeletons e toasts (sonner) em todas as ações.
- **Interface 100% responsiva** — mobile, tablet e desktop.

## 🧱 Arquitetura

```
DeepSearch-Soc/
├── artifacts/
│   ├── api-server/          # Backend Express 5 + Drizzle + Pino
│   └── cve-dashboard/       # Frontend React + Vite + Tailwind + shadcn/ui
├── lib/
│   ├── api-client-react/    # Cliente tipado (React Query)
│   ├── api-spec/            # Contratos OpenAPI compartilhados
│   ├── api-zod/             # Schemas Zod
│   └── db/                  # Drizzle ORM + migrations
├── scripts/                 # Utilitários (import, seed, etc.)
├── render.yaml              # Blueprint de deploy no Render
├── DEPLOY.md                # Guia passo a passo
└── .env.example             # Variáveis de ambiente
```

Monorepo **pnpm workspaces**. Backend e frontend compartilham contratos tipados via `lib/api-spec` + `lib/api-zod`.

## 🚀 Rodando localmente

**Pré-requisitos:** Node 20+, pnpm 9+ (`corepack enable`), banco Postgres (Supabase grátis serve).

```bash
git clone https://github.com/osmarrcs/DeepSearch-Soc.git
cd DeepSearch-Soc
cp .env.example .env         # preencha DATABASE_URL
pnpm install
pnpm --filter @workspace/db migrate    # cria as tabelas
pnpm --filter @workspace/api-server dev   # API  → http://localhost:3000
pnpm --filter @workspace/cve-dashboard dev # Web → http://localhost:5173
```

O Vite já faz proxy de `/api/*` para o backend em dev; não precisa configurar CORS localmente.

## ☁️ Deploy

Guia completo em [`DEPLOY.md`](./DEPLOY.md). Resumo:

1. **Banco:** crie um projeto grátis no [Supabase](https://supabase.com), copie a **Transaction Pooler URL** (porta 6543).
2. **GitHub:** faça push deste repo.
3. **Render:** *New → Blueprint* → aponte para o repo. O `render.yaml` cria API + Static Site automaticamente. Preencha:
   - `DATABASE_URL` (API) — URL do Supabase pooler.
   - `CORS_ORIGIN` (API) — URL do frontend.
   - `VITE_API_URL` (Web) — URL da API.
4. Rode as migrations uma vez (`pnpm --filter @workspace/db migrate` local apontando pra prod, ou via Render Shell).

## 🔐 Variáveis de ambiente

| Var                | Serviço | Descrição                                                  |
| ------------------ | ------- | ---------------------------------------------------------- |
| `DATABASE_URL`     | API     | Postgres (Supabase pooled, `sslmode=require`)              |
| `PORT`             | API     | Injetado pelo Render; fallback local `3000`                |
| `CORS_ORIGIN`      | API     | Origem permitida em produção                               |
| `NODE_ENV`         | API     | `production` no Render                                     |
| `VITE_API_URL`     | Web     | URL pública da API (usado apenas em build de produção)     |

Nada é hardcoded — todas credenciais via env.

## 🧰 Stack técnica

- **Backend:** Express 5, Drizzle ORM, `pg` com SSL, Pino, graceful shutdown.
- **Frontend:** React 18, Vite 5, TanStack Query, Tailwind, shadcn/ui, sonner (toasts), wouter (router).
- **Banco:** Postgres serverless (Supabase / Neon / Railway — compatível).
- **Deploy:** Render Blueprint (`render.yaml`) — 1-click.

## 🛡️ Segurança & resiliência

- SSL obrigatório na conexão com o banco.
- Pool de conexões dimensionado para serverless (idle timeout curto).
- Error handler global sempre devolve JSON.
- `SIGTERM` tratado — deploys/rollbacks no Render sem conexões penduradas.
- Sem credenciais em código, sem `console.log` de dados sensíveis.

## 📝 Licença

MIT © DeepSearch-Soc contributors.
