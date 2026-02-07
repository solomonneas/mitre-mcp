import { describe, it, expect, beforeAll } from "vitest";
import { AttackDataStore } from "../src/data/index.js";
import type { MatrixType, MitreConfig, StixBundle } from "../src/types.js";

const mockBundle: StixBundle = {
  type: "bundle",
  id: "bundle--mapping-test",
  objects: [
    // Techniques for mapping tests
    {
      id: "attack-pattern--t1059",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Command and Scripting Interpreter",
      description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1059" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "execution" },
      ],
      x_mitre_platforms: ["Windows", "Linux", "macOS"],
      x_mitre_data_sources: ["Command: Command Execution"],
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
      x_mitre_data_sources: ["Command: Command Execution", "Process: Process Creation"],
      x_mitre_detection: "Monitor PowerShell execution, script block logging, and encoded commands.",
      x_mitre_is_subtechnique: true,
    },
    {
      id: "attack-pattern--t1566",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Phishing",
      description: "Adversaries may send phishing messages to gain access to victim systems.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1566" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "initial-access" },
      ],
      x_mitre_platforms: ["Windows", "Linux", "macOS"],
      x_mitre_data_sources: ["Network Traffic: Network Traffic Content"],
      x_mitre_detection: "Monitor for suspicious email attachments and links.",
      x_mitre_is_subtechnique: false,
    },
    {
      id: "attack-pattern--t1078",
      type: "attack-pattern",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Valid Accounts",
      description: "Adversaries may obtain and abuse credentials of existing accounts.",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1078" },
      ],
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "initial-access" },
        { kill_chain_name: "mitre-attack", phase_name: "persistence" },
      ],
      x_mitre_platforms: ["Windows", "Linux", "macOS", "Cloud"],
      x_mitre_data_sources: ["Logon Session: Logon Session Creation"],
      x_mitre_detection: "Monitor for unusual account activity.",
      x_mitre_is_subtechnique: false,
    },
    // Tactics
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
      description: "APT28 is attributed to Russia.",
      aliases: ["APT28", "Fancy Bear"],
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
      description: "APT29 is attributed to Russia.",
      aliases: ["APT29", "Cozy Bear"],
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
    // Mitigations
    {
      id: "course-of-action--m1038",
      type: "course-of-action",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      name: "Execution Prevention",
      description: "Block execution of code via application control.",
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
      description: "Information about instances of computer programs.",
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
      id: "rel--1",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "attack-pattern--t1059",
    },
    {
      id: "rel--2",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "attack-pattern--t1566",
    },
    {
      id: "rel--3",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt29",
      target_ref: "attack-pattern--t1566",
    },
    {
      id: "rel--4",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt29",
      target_ref: "attack-pattern--t1078",
    },
    {
      id: "rel--5",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "mitigates",
      source_ref: "course-of-action--m1038",
      target_ref: "attack-pattern--t1059",
    },
    {
      id: "rel--6",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "malware--mimikatz",
      target_ref: "attack-pattern--t1078",
    },
    {
      id: "rel--7",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "uses",
      source_ref: "intrusion-set--apt28",
      target_ref: "malware--mimikatz",
    },
    {
      id: "rel--8",
      type: "relationship",
      created: "2020-01-01T00:00:00Z",
      modified: "2023-01-01T00:00:00Z",
      relationship_type: "detects",
      source_ref: "x-mitre-data-component--proc-creation",
      target_ref: "attack-pattern--t1059",
    },
  ] as any[],
};

function createTestStore(): AttackDataStore {
  const config: MitreConfig = {
    dataDir: "/tmp/test-mitre-mapping",
    matrices: ["enterprise"],
    updateInterval: 86400,
  };
  const store = new AttackDataStore(config);
  const bundles = new Map<MatrixType, StixBundle>();
  bundles.set("enterprise", mockBundle);
  store.loadFromBundles(bundles);
  return store;
}

describe("Mapping - technique search with combined filters", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should find techniques by keyword in name", () => {
    const results = store.searchTechniques({ query: "powershell" });
    expect(results.length).toBe(1);
    expect(results[0].name).toBe("PowerShell");
  });

  it("should find techniques by keyword in description", () => {
    const results = store.searchTechniques({ query: "credentials" });
    expect(results.length).toBe(1);
    expect(results[0].id).toBe("T1078");
  });

  it("should combine tactic and platform filters", () => {
    const results = store.searchTechniques({
      tactic: "initial-access",
      platform: "Cloud",
    });
    expect(results.length).toBe(1);
    expect(results[0].id).toBe("T1078");
  });

  it("should return empty when no match", () => {
    const results = store.searchTechniques({ query: "nonexistent-zzz" });
    expect(results.length).toBe(0);
  });
});

describe("Mapping - group technique overlap", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should find common techniques between groups", () => {
    const apt28 = store.getGroup("G0007")!;
    const apt29 = store.getGroup("G0016")!;

    const apt28Techs = store.getGroupTechniques(apt28.stixId).map((t) => t.technique.id);
    const apt29Techs = store.getGroupTechniques(apt29.stixId).map((t) => t.technique.id);

    const overlap = apt28Techs.filter((t) => apt29Techs.includes(t));
    expect(overlap).toContain("T1566");
  });

  it("should identify unique techniques per group", () => {
    const apt28 = store.getGroup("G0007")!;
    const apt29 = store.getGroup("G0016")!;

    const apt28Techs = new Set(store.getGroupTechniques(apt28.stixId).map((t) => t.technique.id));
    const apt29Techs = new Set(store.getGroupTechniques(apt29.stixId).map((t) => t.technique.id));

    expect(apt28Techs.has("T1059")).toBe(true);
    expect(apt29Techs.has("T1059")).toBe(false);
    expect(apt29Techs.has("T1078")).toBe(true);
    expect(apt28Techs.has("T1078")).toBe(false);
  });
});

describe("Mapping - campaign profiling", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should identify tactic coverage from technique set", () => {
    const techs = ["T1059", "T1566"].map((id) => store.getTechnique(id)!);

    const tacticCoverage: Record<string, string[]> = {};
    for (const tech of techs) {
      for (const tactic of tech.tactics) {
        if (!tacticCoverage[tactic]) tacticCoverage[tactic] = [];
        tacticCoverage[tactic].push(tech.id);
      }
    }

    expect(tacticCoverage["execution"]).toContain("T1059");
    expect(tacticCoverage["initial-access"]).toContain("T1566");
  });

  it("should find groups matching an observed technique set", () => {
    const observedIds = new Set(["T1059", "T1566"]);
    const allGroups = store.getAllGroups();

    const matches = allGroups
      .map((group) => {
        const groupTechs = store.getGroupTechniques(group.stixId).map((t) => t.technique.id);
        const shared = groupTechs.filter((t) => observedIds.has(t));
        return { name: group.name, shared, score: shared.length / observedIds.size };
      })
      .filter((m) => m.shared.length > 0)
      .sort((a, b) => b.score - a.score);

    expect(matches[0].name).toBe("APT28");
    expect(matches[0].score).toBe(1); // APT28 uses both T1059 and T1566
  });

  it("should identify mitigation priorities for observed techniques", () => {
    const observedIds = ["T1059", "T1566"];
    const mitigationMap = new Map<string, string[]>();

    for (const techId of observedIds) {
      const mits = store.getMitigationsForTechnique(techId);
      for (const m of mits) {
        const key = m.mitigation.id;
        if (!mitigationMap.has(key)) mitigationMap.set(key, []);
        mitigationMap.get(key)!.push(techId);
      }
    }

    expect(mitigationMap.has("M1038")).toBe(true);
    expect(mitigationMap.get("M1038")).toContain("T1059");
  });
});

describe("Mapping - software to technique chain", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should trace software to techniques to groups", () => {
    const mimikatz = store.getSoftware("Mimikatz")!;
    const techniques = store.getSoftwareTechniques(mimikatz.stixId);
    expect(techniques.length).toBe(1);
    expect(techniques[0].technique.id).toBe("T1078");

    const groups = store.getSoftwareGroups(mimikatz.stixId);
    expect(groups.length).toBe(1);
    expect(groups[0].group.name).toBe("APT28");
  });
});

describe("Mapping - data source detection coverage", () => {
  let store: AttackDataStore;

  beforeAll(() => {
    store = createTestStore();
  });

  it("should calculate detection stats", () => {
    const allTechniques = store.getAllTechniques();
    const allDataSources = store.getAllDataSources();

    expect(allTechniques.length).toBeGreaterThan(0);
    expect(allDataSources.length).toBeGreaterThan(0);
  });

  it("should find techniques detectable by available data sources", () => {
    const ds = store.getDataSource("Process")!;
    const components = store.getComponentsForDataSource(ds.stixId);

    let detectable = 0;
    for (const comp of components) {
      const techs = store.getTechniquesDetectedByComponent(comp.stixId);
      detectable += techs.length;
    }

    expect(detectable).toBeGreaterThan(0);
  });
});
