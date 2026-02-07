import { homedir } from "node:os";
import { join } from "node:path";
import type { MatrixType, MitreConfig } from "./types.js";

const VALID_MATRICES = new Set(["enterprise", "mobile", "ics"]);

export function loadConfig(): MitreConfig {
  const dataDir =
    process.env.MITRE_DATA_DIR || join(homedir(), ".mitre-mcp", "data");

  const matricesRaw = process.env.MITRE_MATRICES || "enterprise";
  const matrices = matricesRaw
    .split(",")
    .map((m) => m.trim().toLowerCase())
    .filter((m) => VALID_MATRICES.has(m)) as MatrixType[];

  if (matrices.length === 0) {
    matrices.push("enterprise");
  }

  const updateInterval = parseInt(
    process.env.MITRE_UPDATE_INTERVAL || "86400",
    10,
  );

  return {
    dataDir,
    matrices,
    updateInterval: isNaN(updateInterval) ? 86400 : updateInterval,
  };
}
