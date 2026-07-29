# Alterações da versão 12

## Scanner

- período selecionável;
- fontes selecionáveis;
- NVD_API_KEY no backend;
- controle global de taxa da NVD;
- CISA KEV com cache;
- tecnologias consultadas em paralelo;
- inserções no PostgreSQL em lotes;
- termos genéricos removidos do catálogo para reduzir ruído;
- histórico mostra período e fontes.

## Boletim por CVE

- remove o relatório simplificado no estilo Tenable One;
- usa o modelo técnico do Colab;
- consulta NVD, CVE/MITRE, CISA KEV, EPSS e referências;
- Gemini somente sob demanda;
- fallback determinístico quando a chave não estiver configurada;
- cache do relatório por 30 minutos.

## Red Hat

- página independente;
- datas selecionáveis;
- API oficial Red Hat Security Data;
- CVEs críticas e importantes;
- clusters por componente;
- tabela geral e tabela Linux Kernel;
- cruzamento CISA KEV;
- destinatários por variáveis de ambiente.

## Microsoft Patch Tuesday

- página independente;
- datas selecionáveis;
- documentos mensais MSRC/CVRF;
- produtos e KBs;
- severidade e impacto;
- divulgação pública e exploração conhecida;
- cruzamento CISA KEV;
- destinatários por variáveis de ambiente.
