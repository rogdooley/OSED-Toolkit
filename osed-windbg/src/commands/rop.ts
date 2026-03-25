import { Command, CommandResult, ValidationFlags } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { knownPatterns, validateInstructionCandidate } from "../logic/instruction_validation";
import { listModulesWithMitigations } from "./modules";

type ScanOptions = {
  module?: string;
  executableOnly: boolean;
  maxResults: number;
  mode: "fast" | "thorough";
};

function readCandidate(address: bigint, size: number): Uint8Array | undefined {
  try {
    return readMemory(address, size);
  } catch (_error) {
    return undefined;
  }
}

function normalizeScan(options: Record<string, unknown>): ScanOptions {
  return {
    module: options.module as string | undefined,
    executableOnly: (options.executableOnly as boolean | undefined) ?? true,
    maxResults: Math.min((options.maxResults as number | undefined) ?? 50, 200),
    mode: (options.mode as "fast" | "thorough" | undefined) ?? "fast",
  };
}

function validationPass(flags: ValidationFlags): boolean {
  return flags.decoded && Boolean(flags.mnemonicMatch) && flags.executable;
}

function scanForPattern(name: string, bytes: number[], options: ScanOptions): CommandResult {
  const pointerSize = getPointerSize();
  const scan = scanPattern(
    {
      module: options.module,
      executableOnly: options.executableOnly,
      maxResults: options.maxResults,
      chunkSize: options.mode === "thorough" ? 0x1000 : 0x4000,
    },
    Uint8Array.from(bytes),
  );

  const findings: unknown[] = [];
  const rows: Array<Record<string, string>> = [];

  for (const hit of scan.hits) {
    const candidate = readCandidate(hit, bytes.length);
    if (!candidate) {
      continue;
    }

    const validated = validateInstructionCandidate(candidate, true, true);
    if (!validationPass(validated.flags)) {
      continue;
    }

    findings.push({
      address: hit,
      bytes,
      mnemonic: validated.mnemonic,
      flags: validated.flags,
    });

    rows.push({
      address: out.formatAddress(hit, pointerSize),
      mnemonic: validated.mnemonic ?? "unknown",
      bytes: bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" "),
      py: `0x${hit.toString(16).toUpperCase()}`,
    });
  }

  rows.sort((a, b) => (a.address < b.address ? -1 : 1));

  out.section(name);
  out.table(
    [
      { key: "address", header: "Address", width: 18 },
      { key: "mnemonic", header: "Mnemonic", width: 18 },
      { key: "bytes", header: "Bytes", width: 16 },
      { key: "py", header: "Python", width: 14 },
    ],
    rows,
  );

  return {
    command: name,
    args: options as unknown as Record<string, unknown>,
    success: true,
    findings,
    warnings: scan.warnings.map((warning) => `${warning.region}: ${warning.message}`),
    errors: [],
    stats: scan.stats,
  };
}

export function createRopCommands(): Command[] {
  const rop: Command = {
    name: "rop",
    description: "ROP helper entrypoint and module triage.",
    usage: "dx @$osed.rop({ module: 'essfunc', maxResults: 50 })",
    examples: ["dx @$osed.rop({})", "dx @$osed.rop({ module: 'essfunc' })"],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const modules = listModulesWithMitigations(options.module as string | undefined);
      out.section("ROP Module Scope");
      out.table(
        [
          { key: "name", header: "Module", width: 18 },
          { key: "base", header: "Base", width: 18 },
          { key: "size", header: "Size", width: 10 },
        ],
        modules.map((module) => ({
          name: module.name,
          base: out.formatAddress(module.base, 8),
          size: `0x${module.size.toString(16).toUpperCase()}`,
        })),
      );
      out.info("Use find_bytes or rop_suggest for bounded gadget discovery.");
      out.whyItMatters("ROP planning starts with selecting stable module memory ranges.");

      return {
        command: "rop",
        args: options,
        success: true,
        findings: modules,
        warnings: [],
        errors: [],
      };
    },
  };

  const findBytes: Command = {
    name: "find_bytes",
    description: "Find byte sequence hits in executable sections.",
    usage: "dx @$osed.find_bytes({ module: 'essfunc', bytes: [0xFF,0xE4] })",
    examples: [
      "dx @$osed.find_bytes({ module: 'essfunc', bytes: [0xFF, 0xE4] })",
      "dx @$osed.find_bytes({ module: 'essfunc', bytes: [0x58, 0xC3], maxResults: 25 })",
    ],
    schema: {
      module: { type: "string", required: true },
      bytes: { type: "array", elementType: "number", required: true },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const bytes = options.bytes as number[];
      if (bytes.length === 0 || bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 0xff)) {
        throw new Error("bytes must contain 0x00..0xFF integers.");
      }

      const scanOpts = normalizeScan(options);
      const scan = scanPattern(
        {
          module: options.module as string,
          executableOnly: scanOpts.executableOnly,
          maxResults: scanOpts.maxResults,
          chunkSize: scanOpts.mode === "thorough" ? 0x1000 : 0x4000,
        },
        Uint8Array.from(bytes),
      );

      const pointerSize = getPointerSize();
      const rows = scan.hits.map((hit) => ({
        address: out.formatAddress(hit, pointerSize),
        python: `0x${hit.toString(16).toUpperCase()}`,
      }));

      out.section("Find Bytes");
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "python", header: "Python", width: 18 },
        ],
        rows,
      );
      out.whyItMatters("Targeted byte matches accelerate practical gadget and pivot discovery.");

      return {
        command: "find_bytes",
        args: options,
        success: true,
        findings: scan.hits,
        warnings: scan.warnings.map((warning) => `${warning.region}: ${warning.message}`),
        errors: [],
        stats: scan.stats,
      };
    },
  };

  const ropSuggest: Command = {
    name: "rop_suggest",
    description: "Suggest common exploit-friendly gadget patterns.",
    usage: "dx @$osed.rop_suggest({ module: 'essfunc' })",
    examples: ["dx @$osed.rop_suggest({ module: 'essfunc' })", "dx @$osed.rop_suggest({ mode: 'thorough' })"],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const scanOptions = normalizeScan(options);
      const combinedFindings: unknown[] = [];
      const combinedWarnings: string[] = [];
      let combinedStats: Record<string, number> = { sectionsScanned: 0, chunksRead: 0, chunksSkipped: 0, results: 0, stoppedEarly: 0 };

      for (const pattern of knownPatterns()) {
        const result = scanForPattern(`ROP Suggest: ${pattern.name}`, pattern.bytes, scanOptions);
        combinedFindings.push(
          ...result.findings.map((finding) => ({ ...(finding as Record<string, unknown>), pattern: pattern.name })),
        );
        combinedWarnings.push(...result.warnings);
        combinedStats = {
          sectionsScanned: combinedStats.sectionsScanned + (result.stats?.sectionsScanned ?? 0),
          chunksRead: combinedStats.chunksRead + (result.stats?.chunksRead ?? 0),
          chunksSkipped: combinedStats.chunksSkipped + (result.stats?.chunksSkipped ?? 0),
          results: combinedStats.results + (result.stats?.results ?? 0),
          stoppedEarly: combinedStats.stoppedEarly + (result.stats?.stoppedEarly ?? 0),
        };
      }

      out.whyItMatters("Validated gadget suggestions reduce false positives during ROP chain construction.");

      return {
        command: "rop_suggest",
        args: options,
        success: true,
        findings: combinedFindings,
        warnings: combinedWarnings,
        errors: [],
        stats: combinedStats,
      };
    },
  };

  return [rop, findBytes, ropSuggest];
}
