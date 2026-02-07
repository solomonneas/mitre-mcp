import { describe, it, expect } from "vitest";
import {
  parseTechniques,
  parseTactics,
  parseGroups,
  parseSoftware,
  parseMitigations,
  parseDataSources,
  parseDataComponents,
  parseRelationships,
} from "../src/data/parser.js";
import type { StixBundle } from "../src/types.js";
import { ENTERPRISE_TACTIC_ORDER } from "../src/types.js";

const mockBundle: StixBundle = {
  type: "bundle",
  id: "bundle--test",
  objects: [
    // Technique (parent)
    {
      id: "attack-pattern--a1234",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Command and Scripting Interpreter",
      description: "Adversaries may abuse command and script interpreters.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1059", url: "https://attack.mitre.org/techniques/T1059" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "execution" },
      ],
      x_mitre_platforms: ["Windows", "Linux", "macOS"],
      x_mitre_data_sources: ["Command: Command Execution", "Process: Process Creation"],
      x_mitre_detection: "Monitor for execution of commands and scripts.",
      x_mitre_is_subtechnique: false,
    },
    // Sub-technique
    {
      id: "attack-pattern--b5678",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "PowerShell",
      description: "Adversaries may abuse PowerShell commands and scripts.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1059.001", url: "https://attack.mitre.org/techniques/T1059/001" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "execution" },
      ],
      x_mitre_platforms: ["Windows"],
      x_mitre_data_sources: ["Command: Command Execution"],
      x_mitre_detection: "Monitor PowerShell activity.",
      x_mitre_is_subtechnique: true,
    },
    // Deprecated technique
    {
      id: "attack-pattern--deprecated1",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Deprecated Technique",
      description: "This technique is deprecated.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T9999" },
      ],
      x_mitre_deprecated: true,
    },
    // Tactic
    {
      id: "x-mitre-tactic--exec",
      type: "x-mitre-tactic",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Execution",
      description: "The adversary is trying to run malicious code.",
      x_mitre_shortname: "execution",
      external_references: [
        { source_name: "mitre-attack", external_id: "TA0002" },
      ],
    },
    {
      id: "x-mitre-tactic--ia",
      type: "x-mitre-tactic",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Initial Access",
      description: "The adversary is trying to get into your network.",
      x_mitre_shortname: "initial-access",
      external_references: [
        { source_name: "mitre-attack", external_id: "TA0001" },
      ],
    },
    // Group
    {
      id: "intrusion-set--apt28",
      type: "intrusion-set",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "APT28",
      description: "APT28 is a threat group attributed to Russia.",
      aliases: ["APT28", "Fancy Bear", "Sofacy"],
      external_references: [
        { source_name: "mitre-attack", external_id: "G0007" },
      ],
    },
    // Malware
    {
      id: "malware--mimikatz",
      type: "malware",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Mimikatz",
      description: "Mimikatz is a credential dumper.",
      aliases: ["Mimikatz"],
      x_mitre_platforms: ["Windows"],
      external_references: [
        { source_name: "mitre-attack", external_id: "S0002" },
      ],
    },
    // Tool
    {
      id: "tool--cobalt",
      type: "tool",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Cobalt Strike",
      description: "Cobalt Strike is a commercial penetration testing tool.",
      aliases: ["Cobalt Strike"],
      x_mitre_platforms: ["Windows", "Linux"],
      external_references: [
        { source_name: "mitre-attack", external_id: "S0154" },
      ],
    },
    // Course of action (mitigation)
    {
      id: "course-of-action--exec-prev",
      type: "course-of-action",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Execution Prevention",
      description: "Block execution of code on a system through policies.",
      external_references: [
        { source_name: "mitre-attack", external_id: "M1038" },
      ],
    },
    // Data source
    {
      id: "x-mitre-data-source--process",
      type: "x-mitre-data-source",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Process",
      description: "Information about instances of computer programs running on an OS.",
      x_mitre_platforms: ["Windows", "Linux", "macOS"],
      external_references: [
        { source_name: "mitre-attack", external_id: "DS0009" },
      ],
    },
    // Data component
    {
      id: "x-mitre-data-component--proc-creation",
      type: "x-mitre-data-component",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Process Creation",
      description: "Birth of a new running process.",
      x_mitre_data_source_ref: "x-mitre-data-source--process",
    },
    // Relationships
    {
      id: "relationship--1",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "attack-pattern--a1234",
      description: "APT28 uses command interpreters.",
    },
    {
      id: "relationship--2",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "mitigates",
      source_ref: "course-of-action--exec-prev",
      target_ref: "attack-pattern--a1234",
      description: "Execution prevention can block script interpreters.",
    },
    {
      id: "relationship--3",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "detects",
      source_ref: "x-mitre-data-component--proc-creation",
      target_ref: "attack-pattern--a1234",
      description: "Process creation events detect script execution.",
    },
    {
      id: "relationship--4",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "malware--mimikatz",
      description: "APT28 uses Mimikatz.",
    },
    // Deprecated relationship (should be filtered)
    {
      id: "relationship--deprecated",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "attack-pattern--deprecated1",
      x_mitre_deprecated: true,
    },
  ] as any[],
};

describe("parseTechniques", () => {
  it("should parse attack patterns into techniques", () => {
    const techniques = parseTechniques(mockBundle);
    expect(techniques.length).toBe(3);
  });

  it("should extract technique IDs from external references", () => {
    const techniques = parseTechniques(mockBundle);
    const t1059 = techniques.find((t) => t.id === "T1059");
    expect(t1059).toBeDefined();
    expect(t1059!.name).toBe("Command and Scripting Interpreter");
  });

  it("should identify sub-techniques", () => {
    const techniques = parseTechniques(mockBundle);
    const ps = techniques.find((t) => t.id === "T1059.001");
    expect(ps).toBeDefined();
    expect(ps!.isSubtechnique).toBe(true);
    expect(ps!.parentId).toBe("T1059");
  });

  it("should mark parent techniques as not sub-technique", () => {
    const techniques = parseTechniques(mockBundle);
    const parent = techniques.find((t) => t.id === "T1059");
    expect(parent!.isSubtechnique).toBe(false);
    expect(parent!.parentId).toBeNull();
  });

  it("should extract tactics from kill chain phases", () => {
    const techniques = parseTechniques(mockBundle);
    const t1059 = techniques.find((t) => t.id === "T1059");
    expect(t1059!.tactics).toEqual(["execution"]);
  });

  it("should extract platforms", () => {
    const techniques = parseTechniques(mockBundle);
    const t1059 = techniques.find((t) => t.id === "T1059");
    expect(t1059!.platforms).toEqual(["Windows", "Linux", "macOS"]);
  });

  it("should mark deprecated techniques", () => {
    const techniques = parseTechniques(mockBundle);
    const deprecated = techniques.find((t) => t.id === "T9999");
    expect(deprecated).toBeDefined();
    expect(deprecated!.deprecated).toBe(true);
  });

  it("should extract data sources", () => {
    const techniques = parseTechniques(mockBundle);
    const t1059 = techniques.find((t) => t.id === "T1059");
    expect(t1059!.dataSources).toContain("Command: Command Execution");
    expect(t1059!.dataSources).toContain("Process: Process Creation");
  });
});

describe("parseTactics", () => {
  it("should parse tactics", () => {
    const tactics = parseTactics(mockBundle, ENTERPRISE_TACTIC_ORDER);
    expect(tactics.length).toBe(2);
  });

  it("should sort tactics by kill-chain order", () => {
    const tactics = parseTactics(mockBundle, ENTERPRISE_TACTIC_ORDER);
    expect(tactics[0].shortName).toBe("initial-access");
    expect(tactics[1].shortName).toBe("execution");
  });

  it("should extract tactic IDs", () => {
    const tactics = parseTactics(mockBundle, ENTERPRISE_TACTIC_ORDER);
    const execution = tactics.find((t) => t.shortName === "execution");
    expect(execution!.id).toBe("TA0002");
  });
});

describe("parseGroups", () => {
  it("should parse intrusion sets into groups", () => {
    const groups = parseGroups(mockBundle);
    expect(groups.length).toBe(1);
    expect(groups[0].name).toBe("APT28");
  });

  it("should extract aliases", () => {
    const groups = parseGroups(mockBundle);
    expect(groups[0].aliases).toContain("Fancy Bear");
    expect(groups[0].aliases).toContain("Sofacy");
  });

  it("should extract group ID", () => {
    const groups = parseGroups(mockBundle);
    expect(groups[0].id).toBe("G0007");
  });
});

describe("parseSoftware", () => {
  it("should parse both malware and tools", () => {
    const software = parseSoftware(mockBundle);
    expect(software.length).toBe(2);
  });

  it("should set correct type for malware", () => {
    const software = parseSoftware(mockBundle);
    const mimikatz = software.find((s) => s.name === "Mimikatz");
    expect(mimikatz!.type).toBe("malware");
  });

  it("should set correct type for tools", () => {
    const software = parseSoftware(mockBundle);
    const cs = software.find((s) => s.name === "Cobalt Strike");
    expect(cs!.type).toBe("tool");
    expect(cs!.id).toBe("S0154");
  });
});

describe("parseMitigations", () => {
  it("should parse course of actions into mitigations", () => {
    const mitigations = parseMitigations(mockBundle);
    expect(mitigations.length).toBe(1);
    expect(mitigations[0].name).toBe("Execution Prevention");
    expect(mitigations[0].id).toBe("M1038");
  });
});

describe("parseDataSources", () => {
  it("should parse data sources", () => {
    const ds = parseDataSources(mockBundle);
    expect(ds.length).toBe(1);
    expect(ds[0].name).toBe("Process");
    expect(ds[0].id).toBe("DS0009");
  });

  it("should extract platforms", () => {
    const ds = parseDataSources(mockBundle);
    expect(ds[0].platforms).toContain("Windows");
  });
});

describe("parseDataComponents", () => {
  it("should parse data components", () => {
    const dc = parseDataComponents(mockBundle);
    expect(dc.length).toBe(1);
    expect(dc[0].name).toBe("Process Creation");
    expect(dc[0].dataSourceId).toBe("x-mitre-data-source--process");
  });
});

describe("parseRelationships", () => {
  it("should parse non-deprecated relationships", () => {
    const rels = parseRelationships(mockBundle);
    // Should exclude the deprecated one
    expect(rels.length).toBe(4);
  });

  it("should capture relationship types", () => {
    const rels = parseRelationships(mockBundle);
    const uses = rels.filter((r) => r.relationshipType === "uses");
    const mitigates = rels.filter((r) => r.relationshipType === "mitigates");
    const detects = rels.filter((r) => r.relationshipType === "detects");
    expect(uses.length).toBe(2);
    expect(mitigates.length).toBe(1);
    expect(detects.length).toBe(1);
  });

  it("should filter out deprecated relationships", () => {
    const rels = parseRelationships(mockBundle);
    const deprecated = rels.find(
      (r) => r.targetRef === "attack-pattern--deprecated1",
    );
    expect(deprecated).toBeUndefined();
  });
});
