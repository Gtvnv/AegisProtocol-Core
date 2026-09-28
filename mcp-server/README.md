# aegis-knowledge (MCP server local)

Server MCP local ao repositório: uma base de conhecimento versionada sobre o
AegisProtocol-Core — satélites já entregues, status do Roadmap 2, fronteira
de escopo com o Z2A, setup de build (JDK21, falhas pré-existentes conhecidas)
e cautelas operacionais (o que nunca tocar sem pedido explícito). Existe pra
isso não depender só da memória entre sessões nem do doc de compliance
externo (que já ficou indisponível no meio de sessões anteriores).

Registrado em `.mcp.json` na raiz do repo — carrega automaticamente em
sessões do Claude Code abertas nesta pasta.

## Setup

```bash
cd mcp-server
npm install
```

## Tools expostas

- `get_project_overview` — o que é o projeto, relação com o Z2A, fronteira de
  escopo, link do doc de compliance (com a ressalva de disponibilidade),
  arquitetura central, instruções permanentes do usuário. Chamar primeiro.
- `list_satellites` — todos os satélites (filtrável por `wave` e `status`).
- `get_satellite` — detalhe de um satélite por `id`.
- `get_roadmap_status` — progresso resumido do Roadmap 2.
- `get_build_setup` — JDK exigido, gotchas de compilação, contagem de falhas
  pré-existentes conhecidas, protocolo de teste passo-a-passo.
- `get_cautions` — o que nunca fazer sem pedido explícito e como lidar com
  outages conhecidos (filtrável por `severity`).

## Atualizando o conhecimento

Os dados vivem em `data/*.json`, versionados junto com o código — não em
banco, não em memória de sessão. Ao entregar um novo satélite ou fechar um
item do Roadmap 2:

1. Adicionar/atualizar o registro correspondente em `data/satellites.json`
   (status `merged`/`open`/`pending`, PR, branch, `knownLimitations`).
2. Se surgir uma nova cautela operacional (outage, algo pra nunca tocar sem
   pedir), adicionar em `data/cautions.json`.
3. Se mudar algo estrutural do build/teste, atualizar `data/build.json`.

Isso faz parte do mesmo fluxo de "reportar e atualizar documentação" que já
existe pra cada PR — só que aqui, versionado no próprio repo em vez de um
serviço externo.

## Testando manualmente

```bash
npx --yes @modelcontextprotocol/inspector --cli node src/index.js --method tools/list
npx --yes @modelcontextprotocol/inspector --cli node src/index.js --method tools/call --tool-name get_roadmap_status
```
