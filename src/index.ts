import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { AttackDataStore } from "./data/index.js";
import { registerTechniqueTools } from "./tools/techniques.js";
import { registerTacticTools } from "./tools/tactics.js";
import { registerGroupTools } from "./tools/groups.js";
import { registerSoftwareTools } from "./tools/software.js";
import { registerMitigationTools } from "./tools/mitigations.js";
import { registerDataSourceTools } from "./tools/datasources.js";
import { registerMappingTools } from "./tools/mapping.js";
import { registerCampaignTools } from "./tools/campaigns.js";
import { registerManagementTools } from "./tools/management.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

async function main(): Promise<void> {
  const config = loadConfig();

  const server = new McpServer({
    name: "mitre-mcp",
    version: "1.0.0",
    description:
      "MITRE ATT&CK knowledge base MCP server for technique lookup, threat intelligence, detection coverage analysis, and campaign attribution",
  });

  const store = new AttackDataStore(config);

  // Initialize data store (downloads on first run, uses cache after)
  console.error("Loading ATT&CK data...");
  try {
    await store.initialize();
    const stats = store.getStats();
    console.error(
      `ATT&CK data loaded: ${stats.techniques} techniques, ${stats.groups} groups, ${stats.software} software, ${stats.mitigations} mitigations`,
    );
  } catch (error) {
    console.error(
      `Warning: Failed to load ATT&CK data: ${error instanceof Error ? error.message : String(error)}`,
    );
    console.error("Some tools may not work until data is available.");
  }

  // Register all tools
  registerTechniqueTools(server, store);
  registerTacticTools(server, store);
  registerGroupTools(server, store);
  registerSoftwareTools(server, store);
  registerMitigationTools(server, store);
  registerDataSourceTools(server, store);
  registerMappingTools(server, store);
  registerCampaignTools(server, store);
  registerManagementTools(server, store, config);

  // Register resources and prompts
  registerResources(server, store, config);
  registerPrompts(server);

  // Connect to transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("MITRE ATT&CK MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
