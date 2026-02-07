import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { MatrixType, StixBundle } from "../types.js";

const STIX_URLS: Record<MatrixType, string> = {
  enterprise:
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
  mobile:
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
  ics: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
};

interface CacheMetadata {
  lastUpdated: string;
  matrices: string[];
}

function getCachePath(dataDir: string, matrix: MatrixType): string {
  return join(dataDir, `${matrix}-attack.json`);
}

function getMetadataPath(dataDir: string): string {
  return join(dataDir, "metadata.json");
}

export function ensureDataDir(dataDir: string): void {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }
}

export function isCacheStale(
  dataDir: string,
  updateInterval: number,
): boolean {
  const metaPath = getMetadataPath(dataDir);
  if (!existsSync(metaPath)) return true;

  try {
    const meta: CacheMetadata = JSON.parse(readFileSync(metaPath, "utf-8"));
    const lastUpdated = new Date(meta.lastUpdated).getTime();
    const now = Date.now();
    return now - lastUpdated > updateInterval * 1000;
  } catch {
    return true;
  }
}

export function hasCachedData(
  dataDir: string,
  matrices: MatrixType[],
): boolean {
  return matrices.every((m) => existsSync(getCachePath(dataDir, m)));
}

export async function downloadMatrix(
  dataDir: string,
  matrix: MatrixType,
): Promise<StixBundle> {
  const url = STIX_URLS[matrix];
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(
      `Failed to download ${matrix} ATT&CK data: ${response.status} ${response.statusText}`,
    );
  }

  const data = (await response.json()) as StixBundle;
  ensureDataDir(dataDir);
  writeFileSync(getCachePath(dataDir, matrix), JSON.stringify(data));

  return data;
}

export async function downloadAllMatrices(
  dataDir: string,
  matrices: MatrixType[],
): Promise<Map<MatrixType, StixBundle>> {
  ensureDataDir(dataDir);
  const bundles = new Map<MatrixType, StixBundle>();

  for (const matrix of matrices) {
    const bundle = await downloadMatrix(dataDir, matrix);
    bundles.set(matrix, bundle);
  }

  const meta: CacheMetadata = {
    lastUpdated: new Date().toISOString(),
    matrices: matrices as string[],
  };
  writeFileSync(getMetadataPath(dataDir), JSON.stringify(meta, null, 2));

  return bundles;
}

export function loadCachedBundle(
  dataDir: string,
  matrix: MatrixType,
): StixBundle | null {
  const cachePath = getCachePath(dataDir, matrix);
  if (!existsSync(cachePath)) return null;

  try {
    return JSON.parse(readFileSync(cachePath, "utf-8")) as StixBundle;
  } catch {
    return null;
  }
}

export function loadCachedBundles(
  dataDir: string,
  matrices: MatrixType[],
): Map<MatrixType, StixBundle> | null {
  const bundles = new Map<MatrixType, StixBundle>();

  for (const matrix of matrices) {
    const bundle = loadCachedBundle(dataDir, matrix);
    if (!bundle) return null;
    bundles.set(matrix, bundle);
  }

  return bundles;
}

export function getCacheAge(dataDir: string): number | null {
  const metaPath = getMetadataPath(dataDir);
  if (!existsSync(metaPath)) return null;

  try {
    const meta: CacheMetadata = JSON.parse(readFileSync(metaPath, "utf-8"));
    return Date.now() - new Date(meta.lastUpdated).getTime();
  } catch {
    return null;
  }
}

export function getLastUpdated(dataDir: string): string | null {
  const metaPath = getMetadataPath(dataDir);
  if (!existsSync(metaPath)) return null;

  try {
    const meta: CacheMetadata = JSON.parse(readFileSync(metaPath, "utf-8"));
    return meta.lastUpdated;
  } catch {
    return null;
  }
}
