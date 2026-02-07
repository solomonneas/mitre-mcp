import { describe, it, expect, beforeAll } from "vitest";
import { AttackDataStore } from "../src/data/index.js";
import type { MatrixType, MitreConfig, StixBundle } from "../src/types.js";

const mockBundle: StixBundle = {
  type: "bundle",
  id: "bundle--test",
  objects: [
    // Techniques
    {
      id: "attack-pattern--t1059",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Command and Scripting Interpreter",
      description: "Adversaries may abuse command and script interpreters to execute commands.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1059" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "execution" },
      ],
      x_mitre_platforms: ["Windows", "Linux", "macOS"],
      x_mitre_data_sources: ["Command: Command Execution", "Process: Process Creation"],
      x_mitre_detection: "Monitor for execution of commands and scripts.",
      x_mitre_is_subtechnique: false,
    },
    {
      id: "attack-pattern--t1059001",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "PowerShell",
      description: "Adversaries may abuse PowerShell commands and scripts for execution.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1059.001" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "execution" },
      ],
      x_mitre_platforms: ["Windows"],
      x_mitre_data_sources: ["Command: Command Execution"],
      x_mitre_detection: "Monitor PowerShell activity.",
      x_mitre_is_subtechnique: true,
    },
    {
      id: "attack-pattern--t1566",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Phishing",
      description: "Adversaries may send phishing messages to gain access.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1566" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "initial-access" },
      ],
      x_mitre_platforms: ["Windows", "Linux", "macOS"],
      x_mitre_data_sources: ["Network Traffic: Network Traffic Content"],
      x_mitre_detection: "Monitor for suspicious email attachments.",
      x_mitre_is_subtechnique: false,
    },
    {
      id: "attack-pattern--t1078",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Valid Accounts",
      description: "Adversaries may obtain and abuse valid accounts.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1078" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "initial-access" },
        { kill_chain_name: "mitre-attack", phase_name: "persistence" },
        { kill_chain_name: "mitre-attack", phase_name: "privilege-escalation" },
        { kill_chain_name: "mitre-attack", phase_name: "defense-evasion" },
      ],
      x_mitre_platforms: ["Windows", "Linux", "macOS", "Cloud"],
      x_mitre_data_sources: ["Logon Session: Logon Session Creation"],
      x_mitre_detection: "Monitor for unusual account activity.",
      x_mitre_is_subtechnique: false,
    },
    // Tactics
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
    {
      id: "x-mitre-tactic--persist",
      type: "x-mitre-tactic",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Persistence",
      description: "The adversary is trying to maintain their foothold.",
      x_mitre_shortname: "persistence",
      external_references: [
        { source_name: "mitre-attack", external_id: "TA0003" },
      ],
    },
    // Groups
    {
      id: "intrusion-set--apt28",
      type: "intrusion-set",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "APT28",
      description: "APT28 is a threat group attributed to Russia's GRU.",
      aliases: ["APT28", "Fancy Bear", "Sofacy"],
      external_references: [
        { source_name: "mitre-attack", external_id: "G0007" },
      ],
    },
    {
      id: "intrusion-set--apt29",
      type: "intrusion-set",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "APT29",
      description: "APT29 is a threat group attributed to Russia's SVR.",
      aliases: ["APT29", "Cozy Bear", "The Dukes"],
      external_references: [
        { source_name: "mitre-attack", external_id: "G0016" },
      ],
    },
    // Software
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
    // Mitigations
    {
      id: "course-of-action--m1038",
      type: "course-of-action",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Execution Prevention",
      description: "Block execution of code on a system through application control policies.",
      external_references: [
        { source_name: "mitre-attack", external_id: "M1038" },
      ],
    },
    {
      id: "course-of-action--m1017",
      type: "course-of-action",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "User Training",
      description: "Train users to be aware of social engineering techniques.",
      external_references: [
        { source_name: "mitre-attack", external_id: "M1017" },
      ],
    },
    // Data sources
    {
      id: "x-mitre-data-source--process",
      type: "x-mitre-data-source",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Process",
      description: "Information about instances of computer programs.",
      x_mitre_platforms: ["Windows", "Linux", "macOS"],
      external_references: [
        { source_name: "mitre-attack", external_id: "DS0009" },
      ],
    },
    // Data components
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
      id: "rel--1",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "attack-pattern--t1059",
      description: "APT28 uses command interpreters.",
    },
    {
      id: "rel--2",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "attack-pattern--t1566",
      description: "APT28 uses phishing.",
    },
    {
      id: "rel--3",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt29",
      target_ref: "attack-pattern--t1566",
      description: "APT29 uses phishing.",
    },
    {
      id: "rel--4",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt29",
      target_ref: "attack-pattern--t1078",
      description: "APT29 uses valid accounts.",
    },
    {
      id: "rel--5",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "malware--mimikatz",
      description: "APT28 uses Mimikatz.",
    },
    {
      id: "rel--6",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "mitigates",
      source_ref: "course-of-action--m1038",
      target_ref: "attack-pattern--t1059",
      description: "Execution prevention blocks command interpreters.",
    },
    {
      id: "rel--7",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "mitigates",
      source_ref: "course-of-action--m1017",
      target_ref: "attack-pattern--t1566",
      description: "User training reduces phishing success.",
    },
    {
      id: "rel--8",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "detects",
      source_ref: "x-mitre-data-component--proc-creation",
      target_ref: "attack-pattern--t1059",
      description: "Process creation events detect command execution.",
    },
    {
      id: "rel--9",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "malware--mimikatz",
      target_ref: "attack-pattern--t1078",
      description: "Mimikatz can dump valid credentials.",
    },
  ] as any[],
};

function createTestStore(): AttackDataStore {
  const config: MitreConfig = {
    dataDir: "/tmp/test-mitre",
    matrices: ["enterprise"],
    updateInterval: 86400,
  };
  const store = new AttackDataStore(config);
  const bundles = new Map<MatrixType, StixBundle>();
  bundles.set("enterprise", mockBundle);
  store.loadFromBundles(bundles);
  return store;
}

describe("AttackDataStore - Technique queries", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should get technique by ID", () => {
    const t = store.getTechnique("T1059");
    expect(t).toBeDefined();
    expect(t!.name).toBe("Command and Scripting Interpreter");
  });

  it("should be case-insensitive for technique lookup", () => {
    const t = store.getTechnique("t1059");
    expect(t).toBeDefined();
  });

  it("should return undefined for missing technique", () => {
    const t = store.getTechnique("T9999");
    expect(t).toBeUndefined();
  });

  it("should list all non-deprecated techniques", () => {
    const all = store.getAllTechniques();
    expect(all.length).toBe(4);
  });

  it("should search techniques by keyword", () => {
    const results = store.searchTechniques({ query: "powershell" });
    expect(results.length).toBe(1);
    expect(results[0].id).toBe("T1059.001");
  });

  it("should search techniques by tactic", () => {
    const results = store.searchTechniques({ tactic: "execution" });
    expect(results.length).toBe(2); // T1059 and T1059.001
  });

  it("should search techniques by platform", () => {
    const results = store.searchTechniques({ platform: "Cloud" });
    expect(results.length).toBe(1);
    expect(results[0].id).toBe("T1078");
  });

  it("should filter sub-techniques", () => {
    const subs = store.searchTechniques({ isSubtechnique: true });
    expect(subs.length).toBe(1);
    expect(subs[0].id).toBe("T1059.001");
  });

  it("should get sub-techniques for a parent", () => {
    const subs = store.getSubtechniques("T1059");
    expect(subs.length).toBe(1);
    expect(subs[0].id).toBe("T1059.001");
  });
});

describe("AttackDataStore - Tactic queries", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should get tactic by ID", () => {
    const t = store.getTactic("TA0002");
    expect(t).toBeDefined();
    expect(t!.name).toBe("Execution");
  });

  it("should get tactic by short name", () => {
    const t = store.getTactic("execution");
    expect(t).toBeDefined();
    expect(t!.id).toBe("TA0002");
  });

  it("should list tactics in kill-chain order", () => {
    const tactics = store.getAllTactics();
    expect(tactics.length).toBe(3);
    expect(tactics[0].shortName).toBe("initial-access");
    expect(tactics[1].shortName).toBe("execution");
  });

  it("should get techniques for a tactic", () => {
    const techs = store.getTechniquesForTactic("execution");
    expect(techs.length).toBe(2);
  });
});

describe("AttackDataStore - Group queries", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should get group by ID", () => {
    const g = store.getGroup("G0007");
    expect(g).toBeDefined();
    expect(g!.name).toBe("APT28");
  });

  it("should get group by name", () => {
    const g = store.getGroup("APT28");
    expect(g).toBeDefined();
    expect(g!.id).toBe("G0007");
  });

  it("should get group by alias", () => {
    const g = store.getGroup("Fancy Bear");
    expect(g).toBeDefined();
    expect(g!.name).toBe("APT28");
  });

  it("should search groups by keyword", () => {
    const results = store.searchGroups({ query: "Russia" });
    expect(results.length).toBe(2);
  });

  it("should search groups by technique", () => {
    const results = store.searchGroups({ technique: "T1059" });
    expect(results.length).toBe(1);
    expect(results[0].name).toBe("APT28");
  });

  it("should get group techniques", () => {
    const group = store.getGroup("G0007")!;
    const techs = store.getGroupTechniques(group.stixId);
    expect(techs.length).toBe(2); // T1059 and T1566
  });

  it("should get group software", () => {
    const group = store.getGroup("G0007")!;
    const sw = store.getGroupSoftware(group.stixId);
    expect(sw.length).toBe(1);
    expect(sw[0].software.name).toBe("Mimikatz");
  });
});

describe("AttackDataStore - Software queries", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should get software by ID", () => {
    const s = store.getSoftware("S0154");
    expect(s).toBeDefined();
    expect(s!.name).toBe("Cobalt Strike");
  });

  it("should get software by name", () => {
    const s = store.getSoftware("Mimikatz");
    expect(s).toBeDefined();
    expect(s!.type).toBe("malware");
  });

  it("should search software by type", () => {
    const tools = store.searchSoftware({ type: "tool" });
    expect(tools.length).toBe(1);
    expect(tools[0].name).toBe("Cobalt Strike");
  });

  it("should get software techniques", () => {
    const s = store.getSoftware("Mimikatz")!;
    const techs = store.getSoftwareTechniques(s.stixId);
    expect(techs.length).toBe(1);
    expect(techs[0].technique.id).toBe("T1078");
  });

  it("should get software groups", () => {
    const s = store.getSoftware("Mimikatz")!;
    const groups = store.getSoftwareGroups(s.stixId);
    expect(groups.length).toBe(1);
    expect(groups[0].group.name).toBe("APT28");
  });
});

describe("AttackDataStore - Mitigation queries", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should get mitigation by ID", () => {
    const m = store.getMitigation("M1038");
    expect(m).toBeDefined();
    expect(m!.name).toBe("Execution Prevention");
  });

  it("should get mitigations for a technique", () => {
    const mits = store.getMitigationsForTechnique("T1059");
    expect(mits.length).toBe(1);
    expect(mits[0].mitigation.name).toBe("Execution Prevention");
  });

  it("should get techniques for a mitigation", () => {
    const techs = store.getTechniquesForMitigation("M1038");
    expect(techs.length).toBe(1);
    expect(techs[0].technique.id).toBe("T1059");
  });

  it("should search mitigations by keyword", () => {
    const results = store.searchMitigations("training");
    expect(results.length).toBe(1);
    expect(results[0].name).toBe("User Training");
  });
});

describe("AttackDataStore - Data source queries", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should get data source by ID", () => {
    const ds = store.getDataSource("DS0009");
    expect(ds).toBeDefined();
    expect(ds!.name).toBe("Process");
  });

  it("should get data source by name", () => {
    const ds = store.getDataSource("Process");
    expect(ds).toBeDefined();
  });

  it("should get components for a data source", () => {
    const ds = store.getDataSource("DS0009")!;
    const components = store.getComponentsForDataSource(ds.stixId);
    expect(components.length).toBe(1);
    expect(components[0].name).toBe("Process Creation");
  });

  it("should get techniques detected by a component", () => {
    const components = store.getDataComponents();
    const procCreation = components.find((c) => c.name === "Process Creation")!;
    const techs = store.getTechniquesDetectedByComponent(procCreation.stixId);
    expect(techs.length).toBe(1);
    expect(techs[0].id).toBe("T1059");
  });
});

describe("AttackDataStore - Stats", () => {
  it("should return correct statistics", () => {
    const store = createTestStore();
    const stats = store.getStats();
    expect(stats.techniques).toBe(4);
    expect(stats.tactics).toBe(3);
    expect(stats.groups).toBe(2);
    expect(stats.software).toBe(2);
    expect(stats.mitigations).toBe(2);
    expect(stats.dataSources).toBe(1);
    expect(stats.relationships).toBeGreaterThan(0);
  });
});
