import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";

export function registerCampaignTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_campaign_profile",
    "Build a technique profile from observed techniques for campaign analysis and attribution",
    {
      techniques: z
        .array(z.string())
        .describe("List of observed technique IDs (e.g., ['T1059.001', 'T1053.005'])"),
    },
    async ({ techniques }) => {
      try {
        const observedTechniques = techniques
          .map((id) => store.getTechnique(id))
          .filter((t): t is NonNullable<typeof t> => t !== null && t !== undefined);

        if (observedTechniques.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: "No valid techniques found from the provided IDs",
              },
            ],
            isError: true,
          };
        }

        // Tactic coverage
        const tacticCoverage: Record<string, string[]> = {};
        for (const tech of observedTechniques) {
          for (const tactic of tech.tactics) {
            if (!tacticCoverage[tactic]) tacticCoverage[tactic] = [];
            tacticCoverage[tactic].push(`${tech.id} - ${tech.name}`);
          }
        }

        // Find likely groups based on technique overlap
        const observedIds = new Set(observedTechniques.map((t) => t.id));
        const allGroups = store.getAllGroups();

        const likelyGroups = allGroups
          .map((group) => {
            const groupTechs = store
              .getGroupTechniques(group.stixId)
              .map((t) => t.technique.id);
            const shared = groupTechs.filter((t) => observedIds.has(t));
            return {
              group: `${group.id} - ${group.name}`,
              overlapScore: Math.round(
                (shared.length / observedIds.size) * 100,
              ),
              sharedTechniques: shared,
              totalGroupTechniques: groupTechs.length,
            };
          })
          .filter((m) => m.sharedTechniques.length > 0)
          .sort((a, b) => b.overlapScore - a.overlapScore)
          .slice(0, 10);

        // Find likely software
        const allSoftware = store.getAllSoftware();
        const likelySoftware = allSoftware
          .map((sw) => {
            const swTechs = store
              .getSoftwareTechniques(sw.stixId)
              .map((t) => t.technique.id);
            const shared = swTechs.filter((t) => observedIds.has(t));
            return {
              software: `${sw.id} - ${sw.name} (${sw.type})`,
              overlapScore: Math.round(
                (shared.length / observedIds.size) * 100,
              ),
              sharedTechniques: shared,
            };
          })
          .filter((m) => m.sharedTechniques.length > 0)
          .sort((a, b) => b.overlapScore - a.overlapScore)
          .slice(0, 10);

        // Suggest next techniques commonly seen with these
        // Look at what the top groups also use but we haven't observed
        const suggestedNext = new Map<string, number>();
        for (const match of likelyGroups.slice(0, 3)) {
          const group = store.getGroup(match.group.split(" - ")[0]);
          if (!group) continue;
          const groupTechs = store.getGroupTechniques(group.stixId);
          for (const t of groupTechs) {
            if (!observedIds.has(t.technique.id)) {
              suggestedNext.set(
                `${t.technique.id} - ${t.technique.name}`,
                (suggestedNext.get(`${t.technique.id} - ${t.technique.name}`) || 0) + 1,
              );
            }
          }
        }

        const suggestedNextTechniques = [...suggestedNext.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([tech]) => tech);

        // Mitigation priorities
        const mitigationMap = new Map<
          string,
          { name: string; techniquesAddressed: string[] }
        >();
        for (const tech of observedTechniques) {
          const mits = store.getMitigationsForTechnique(tech.id);
          for (const m of mits) {
            const key = m.mitigation.id;
            if (!mitigationMap.has(key)) {
              mitigationMap.set(key, {
                name: `${m.mitigation.id} - ${m.mitigation.name}`,
                techniquesAddressed: [],
              });
            }
            mitigationMap.get(key)!.techniquesAddressed.push(tech.id);
          }
        }

        const mitigationPriorities = [...mitigationMap.values()]
          .sort(
            (a, b) =>
              b.techniquesAddressed.length - a.techniquesAddressed.length,
          )
          .slice(0, 10);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  observedTechniqueCount: observedTechniques.length,
                  tacticCoverage,
                  likelyGroups,
                  likelySoftware,
                  suggestedNextTechniques,
                  mitigationPriorities,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
