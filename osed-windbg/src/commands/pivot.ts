import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { validateInstructionCandidate } from "../logic/instruction_validation";

const PIVOT_PATTERNS: Array<{ sequence: string; bytes: number[] }> = [
  { sequence: "xchg eax, esp ; ret", bytes: [0x94, 0xc3] },
  { sequence: "push esp ; ret", bytes: [0x54, 0xc3] },
  { sequence: "mov esp, ebp ; ret", bytes: [0x8b, 0xe5, 0xc3] },
];

export function createPivotCommand(): Command {
  return {
    name: "pivots",
    description: "Scan for stack pivot candidates.",
    usage: "dx @$osed.pivots({ module: 'essfunc', maxResults: 50 })",
    examples: ["dx @$osed.pivots({ module: 'essfunc' })", "dx @$osed.pivots({ mode: 'thorough' })"],
    schema: {
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      mode: { type: "string", enum: ["fast", "thorough"], default: "fast" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const findings: unknown[] = [];
      const warnings: string[] = [];

      for (const pivot of PIVOT_PATTERNS) {
        const scan = scanPattern(
          {
            module: options.module as string | undefined,
            executableOnly: (options.executableOnly as boolean | undefined) ?? true,
            maxResults: (options.maxResults as number | undefined) ?? 50,
            chunkSize: (options.mode as string) === "thorough" ? 0x1000 : 0x4000,
          },
          Uint8Array.from(pivot.bytes),
        );

        warnings.push(...scan.warnings.map((warning) => `${warning.region}: ${warning.message}`));

        for (const hit of scan.hits) {
          const candidate = readMemory(hit, pivot.bytes.length);
          const validated = validateInstructionCandidate(candidate, true, true);
          if (!validated.flags.decoded || !validated.flags.mnemonicMatch || !validated.flags.executable) {
            continue;
          }

          findings.push({
            address: hit,
            sequence: pivot.sequence,
            offset: `0x${hit.toString(16).toUpperCase()}`,
            flags: validated.flags,
          });
        }
      }

      findings.sort((a, b) => ((a as { address: bigint }).address < (b as { address: bigint }).address ? -1 : 1));

      out.section("Stack Pivot Candidates");
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "sequence", header: "Sequence", width: 22 },
          { key: "python", header: "Python", width: 18 },
        ],
        findings.map((finding) => ({
          address: out.formatAddress((finding as { address: bigint }).address, pointerSize),
          sequence: (finding as { sequence: string }).sequence,
          python: `0x${(finding as { address: bigint }).address.toString(16).toUpperCase()}`,
        })),
      );
      out.whyItMatters("Stack pivots transition execution into attacker-controlled ROP chains.");

      return {
        command: "pivots",
        args: options,
        success: true,
        findings,
        warnings,
        errors: [],
      };
    },
  };
}
