# Correção de conexão Supabase + Render

## Formato esperado

```text
postgresql://postgres.PROJECT_REF:PASSWORD@aws-0-REGION.pooler.supabase.com:6543/postgres
```

Pontos obrigatórios:

- usuário `postgres.PROJECT_REF`;
- `:` antes da senha;
- `@` antes do hostname `aws-...`;
- porta `6543` para Transaction mode;
- senha percent-encoded se contiver símbolos reservados de URL.

O código desta versão remove parâmetros SSL da URI e configura TLS explicitamente
no `pg`. Portanto, não é necessário anexar `?sslmode=require`.

## Endpoints

- `/api/healthz`: testa somente o Express.
- `/api/healthz/db`: testa DNS, TLS, autenticação e uma consulta no Supabase.

## Logs esperados

```text
[db] connection established
[db] bootstrap complete
Server listening
```
