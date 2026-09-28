import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, "..", "data");

function loadJson(file) {
  return JSON.parse(readFileSync(path.join(dataDir, file), "utf-8"));
}

const overview = loadJson("overview.json");
const satellites = loadJson("satellites.json");
const build = loadJson("build.json");
const cautions = loadJson("cautions.json");

function textResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

const server = new McpServer({
  name: "aegis-knowledge",
  version: "1.0.0",
});

server.registerTool(
  "get_project_overview",
  {
    title: "Visão geral do AegisProtocol-Core",
    description:
      "O que é o AegisProtocol-Core, sua relação com o Meta-Framework Z2A, a regra de fronteira de escopo, o link do doc de compliance (e sua ressalva de disponibilidade), a arquitetura central (Ômega chain, S.H.I.E.L.D., PrivacyGate) e as instruções permanentes do usuário sobre o fluxo de trabalho. Chamar isto primeiro em qualquer sessão nova neste repo.",
  },
  async () => textResult(overview)
);

server.registerTool(
  "list_satellites",
  {
    title: "Lista os satélites (evoluções) do AegisProtocol",
    description:
      "Lista todos os satélites já entregues ou planejados, com PR, branch, status e limitações conhecidas. Filtrável por onda (original = os 7 primeiros itens do roadmap; roadmap2 = itens de follow-up nascidos das limitações do primeiro round) e por status.",
    inputSchema: {
      wave: z.enum(["original", "roadmap2", "all"]).optional().describe("Filtra por onda do roadmap. Padrão: all."),
      status: z.enum(["merged", "open", "pending", "all"]).optional().describe("Filtra por status do PR. Padrão: all."),
    },
  },
  async ({ wave, status }) => {
    let result = satellites;
    if (wave && wave !== "all") {
      result = result.filter((s) => s.wave === wave);
    }
    if (status && status !== "all") {
      result = result.filter((s) => s.status === status);
    }
    return textResult(result);
  }
);

server.registerTool(
  "get_satellite",
  {
    title: "Detalhe de um satélite específico",
    description: "Retorna o registro completo de um satélite pelo seu id (ver list_satellites para os ids disponíveis).",
    inputSchema: {
      id: z.string().describe("id do satélite, ex: 'consent-gate', 'omega-legacy-actor-closure'."),
    },
  },
  async ({ id }) => {
    const found = satellites.find((s) => s.id === id);
    if (!found) {
      const ids = satellites.map((s) => s.id).join(", ");
      return textResult({ error: `Satélite '${id}' não encontrado.`, availableIds: ids });
    }
    return textResult(found);
  }
);

server.registerTool(
  "get_roadmap_status",
  {
    title: "Status do Roadmap 2",
    description:
      "Resumo do progresso do Roadmap 2 (os itens de follow-up nascidos das limitações conhecidas do primeiro round de 7 satélites): quantos merged, quantos com PR aberto, quantos ainda não iniciados — e quais são.",
  },
  async () => {
    const roadmap2 = satellites.filter((s) => s.wave === "roadmap2").sort((a, b) => a.order - b.order);
    const summary = {
      total: roadmap2.length,
      merged: roadmap2.filter((s) => s.status === "merged").length,
      open: roadmap2.filter((s) => s.status === "open").length,
      pending: roadmap2.filter((s) => s.status === "pending").length,
      items: roadmap2.map((s) => ({ id: s.id, name: s.name, pr: s.pr, status: s.status })),
    };
    return textResult(summary);
  }
);

server.registerTool(
  "get_build_setup",
  {
    title: "Como compilar e testar este repo",
    description:
      "JDK exigido (21, não o do sistema), o gotcha de recompilação em background com JDK25 contaminando target/classes, por que os diagnostics do IDE não são confiáveis sozinhos, a contagem exata de falhas de teste pré-existentes e conhecidas (18), e o protocolo passo-a-passo pra rodar a suíte com segurança.",
  },
  async () => textResult(build)
);

server.registerTool(
  "get_cautions",
  {
    title: "Cautelas operacionais ativas neste repo/sessão",
    description:
      "Coisas que NUNCA fazer sem pedido explícito (tocar a migração Java25 stashed/branch appmod/*, commitar direto em main) e como lidar com outages transientes conhecidos (classificador do Bash/PowerShell, conector Claude Docs). Filtrável por severidade.",
    inputSchema: {
      severity: z.enum(["high", "medium", "low", "all"]).optional().describe("Filtra por severidade. Padrão: all."),
    },
  },
  async ({ severity }) => {
    const result = severity && severity !== "all" ? cautions.filter((c) => c.severity === severity) : cautions;
    return textResult(result);
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
