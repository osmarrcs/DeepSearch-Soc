# DeepSearch SOC v12

Aplicação web para pesquisa de vulnerabilidades, triagem e geração de relatórios técnicos de Threat Intelligence.

## Principais módulos

- **Varredura com período selecionável**: NVD/NIST e CISA KEV como fontes rápidas padrão; CIRCL e OSV opcionais.
- **Boletim por CVE**: correlaciona NVD, CVE/MITRE, CISA KEV, EPSS, referências do fabricante e Gemini.
- **Relatório Diário Red Hat**: usa a API oficial de Security Data, clusters por componente e seção separada para Linux Kernel.
- **Microsoft Patch Tuesday**: usa os documentos oficiais do MSRC/CVRF, produtos, KBs, severidade e exploração conhecida.
- **Histórico de varreduras**: armazena período, fontes, tecnologias e total encontrado.
- **PostgreSQL/Supabase**: bootstrap idempotente no início da API.

## Desempenho e consumo de tokens

A varredura **não chama o Gemini**. Ela utiliza APIs públicas e salva as CVEs no banco. O Gemini é chamado somente quando o usuário abre **Boletim por CVE** e solicita a correlação completa.

O modo recomendado é:

```text
NVD + CISA KEV
```

O CISA KEV é baixado uma vez e mantido em cache por 15 minutos. As chamadas NVD são controladas por uma fila global. Quando `NVD_API_KEY` está configurada, a fila usa intervalo menor; sem a chave, o scanner reduz o ritmo para respeitar o limite público.

## Estrutura

```text
DeepSearch-Soc/
├── artifacts/
│   ├── api-server/          # Express + fontes + relatórios
│   └── cve-dashboard/       # React + Vite
├── lib/
│   ├── api-client-react/
│   ├── api-spec/
│   ├── api-zod/
│   └── db/                  # Drizzle + bootstrap PostgreSQL
├── render.yaml
├── DEPLOY.md
└── .env.example
```

## Páginas da aplicação

```text
/
/varredura
/vulnerabilidades
/varreduras
/boletim
/relatorios/red-hat
/relatorios/patch-tuesday
```

## Variáveis principais

| Variável | Finalidade |
|---|---|
| `DATABASE_URL` | Conexão Supabase/PostgreSQL |
| `CORS_ORIGIN` | URL pública do dashboard |
| `VITE_API_URL` | URL pública da API |
| `NVD_API_KEY` | Aumenta a capacidade de consulta da NVD |
| `GEMINI_API_KEY` | Correlação por IA somente no boletim por CVE |
| `GEMINI_MODEL` | Modelo principal do Gemini |
| `SCAN_TECH_CONCURRENCY` | Quantidade de tecnologias processadas em paralelo |
| `REDHAT_JFPE_TO` | Destinatários da opção JFPE |
| `REDHAT_TRF5_TO` | Destinatários da opção TRF5 |
| `REDHAT_REPORT_CC` | Cópia dos relatórios Red Hat |
| `MICROSOFT_REPORT_TO` | Destinatários do Patch Tuesday |
| `MICROSOFT_REPORT_CC` | Cópia do Patch Tuesday |

Os valores reais devem ficar no Render ou no `.env` local. Não coloque senhas, chaves ou endereços internos diretamente no código.

## Execução local

```bash
corepack enable
pnpm install
pnpm --filter @workspace/db db:bootstrap
pnpm --filter @workspace/api-server dev
pnpm --filter @workspace/cve-dashboard dev
```

Consulte [`DEPLOY.md`](./DEPLOY.md) para o procedimento completo no Render.
