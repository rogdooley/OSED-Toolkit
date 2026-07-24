import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory, readPointer } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { decodeOffsetNeedle, generateCyclicPattern, generateMsfPattern } from "../logic/pattern_logic";
import { findModuleByAddress, listModulesWithMitigations, ModuleMitigation } from "./modules";

type RegisterSnapshot = {
  ip?: bigint;
  ipName?: string;
  sp?: bigint;
  spName?: string;
  exceptionCode?: bigint;
  all: Array<{ name: string; value: bigint }>;
};

type TriState = "yes" | "no" | "unknown";

function safeGet(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  try {
    return (value as Record<string, unknown>)[key];
  } catch (_error) {
    return undefined;
  }
}

function safeKeys(value: unknown): string[] {
  if (!value || typeof value !== "object") {
    return [];
  }
  try {
    return Object.keys(value as Record<string, unknown>);
  } catch (_error) {
    return [];
  }
}

function toBigInt(value: unknown): bigint | undefined {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
    return BigInt(Math.trunc(value));
  }
  if (typeof value === "string") {
    const text = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(text)) {
      return BigInt(text);
    }
    if (/^[0-9a-fA-F]+$/.test(text)) {
      return BigInt(`0x${text}`);
    }
    if (/^[0-9]+$/.test(text)) {
      return BigInt(text);
    }
  }
  if (value && typeof value === "object") {
    const nested = ["value", "Value", "address", "Address", "targetLocation"];
    for (const key of nested) {
      const parsed = toBigInt(safeGet(value, key));
      if (parsed !== undefined) {
        return parsed;
      }
    }
    try {
      const valueOf = safeGet(value, "valueOf");
      if (typeof valueOf === "function") {
        const resolved = (valueOf as () => unknown).call(value);
        if (resolved !== value) {
          const parsed = toBigInt(resolved);
          if (parsed !== undefined) {
            return parsed;
          }
        }
      }
    } catch (_error) {
      // ignore
    }
    try {
      const asString = safeGet(value, "toString");
      if (typeof asString === "function") {
        const str = (asString as () => unknown).call(value);
        if (typeof str === "string" && str !== "[object Object]") {
          return toBigInt(str);
        }
      }
    } catch (_error) {
      // ignore
    }
  }
  return undefined;
}

function toArray(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function") {
    try {
      return Array.from(value as Iterable<unknown>);
    } catch (_error) {
      return [];
    }
  }
  return [];
}

function readRegisters(pointerSize: 4 | 8): RegisterSnapshot {
  const thread = host.currentThread as Record<string, unknown>;
  const regsRoot = safeGet(thread, "Registers");
  const userRegs = safeGet(regsRoot, "User") ?? regsRoot;

  const all: Array<{ name: string; value: bigint }> = [];
  for (const key of safeKeys(userRegs)) {
    const parsed = toBigInt(safeGet(userRegs, key));
    if (parsed !== undefined) {
      all.push({ name: key, value: parsed });
    }
  }

  const pick = (...names: string[]): { name: string; value: bigint } | undefined => {
    for (const candidate of names) {
      const found = all.find((entry) => entry.name.toLowerCase() === candidate.toLowerCase());
      if (found) {
        return found;
      }
    }
    return undefined;
  };

  const ip = pointerSize === 8 ? pick("rip", "eip") : pick("eip", "rip");
  const sp = pointerSize === 8 ? pick("rsp", "esp") : pick("esp", "rsp");
  const ex = pick("exceptioncode", "exception", "lastExceptionCode");

  return {
    ip: ip?.value,
    ipName: ip?.name,
    sp: sp?.value,
    spName: sp?.name,
    exceptionCode: ex?.value,
    all,
  };
}

function findOffset(raw: bigint | undefined, maxLen: number): { kind: "msf" | "cyclic"; offset: number } | undefined {
  if (raw === undefined) {
    return undefined;
  }

  const low = Number(raw & BigInt(0xffffffff));
  const candidates = [
    { kind: "msf" as const, haystack: generateMsfPattern(Math.min(maxLen, 20280)) },
    { kind: "cyclic" as const, haystack: generateCyclicPattern(Math.max(maxLen, 20000)) },
  ];

  for (const candidate of candidates) {
    const needle = decodeOffsetNeedle(low);
    const offset = candidate.haystack.indexOf(needle);
    if (offset >= 0) {
      return { kind: candidate.kind, offset };
    }
  }

  return undefined;
}

function scanStack(sp: bigint | undefined, size: number): { base?: bigint; bytes?: Uint8Array; warning?: string } {
  if (sp === undefined) {
    return { warning: "Stack pointer unavailable." };
  }
  try {
    const bytes = readMemory(sp, size);
    return { base: sp, bytes };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { warning: `Stack read failed: ${msg}` };
  }
}

type ShellcodeHit = { address: bigint; reason: string };

const SHELLCODE_PROLOGUES: { bytes: number[]; label: string }[] = [
  { bytes: [0xfc, 0xe8], label: "CLD;CALL stub" },
  { bytes: [0x64, 0xa1, 0x30, 0x00, 0x00, 0x00], label: "PEB via fs:[0x30]" },
  { bytes: [0x31, 0xc9, 0xb1], label: "XOR ECX,ECX;MOV CL,N (decoder)" },
  { bytes: [0x31, 0xc9, 0xb5], label: "XOR ECX,ECX;MOV CH,N (decoder)" },
  { bytes: [0x89, 0xe5, 0x31, 0xc0], label: "MOV EBP,ESP;XOR EAX,EAX" },
];

function matchesAt(data: Uint8Array, offset: number, pattern: number[]): boolean {
  if (offset + pattern.length > data.length) return false;
  for (let j = 0; j < pattern.length; j += 1) {
    if (data[offset + j] !== pattern[j]) return false;
  }
  return true;
}

function shannonEntropy(data: Uint8Array, start: number, length: number): number {
  const counts = new Uint32Array(256);
  const end = Math.min(start + length, data.length);
  const n = end - start;
  if (n <= 0) return 0;
  for (let i = start; i < end; i += 1) {
    counts[data[i]] += 1;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue;
    const p = counts[i] / n;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isRepeatingDwords(data: Uint8Array, start: number, length: number): boolean {
  if (length < 8) return false;
  const d0 = data[start];
  const d1 = data[start + 1];
  const d2 = data[start + 2];
  const d3 = data[start + 3];
  for (let i = 4; i < length && start + i + 3 < data.length; i += 4) {
    if (data[start + i] !== d0 || data[start + i + 1] !== d1 ||
        data[start + i + 2] !== d2 || data[start + i + 3] !== d3) {
      return false;
    }
  }
  return true;
}

function isMonotonicBytes(data: Uint8Array, start: number, length: number): boolean {
  let ascending = 0;
  const end = Math.min(start + length, data.length);
  for (let i = start + 1; i < end; i += 1) {
    if (data[i] === data[i - 1] + 1) ascending += 1;
  }
  return ascending > (length - 1) * 0.7;
}

function countAlignedModulePointers(data: Uint8Array, start: number, length: number): number {
  let count = 0;
  for (let i = 0; i + 3 < length; i += 4) {
    const val = BigInt(data[start + i] | (data[start + i + 1] << 8) |
                       (data[start + i + 2] << 16) | (data[start + i + 3] << 24)) & BigInt(0xffffffff);
    if (val > BigInt(0x10000) && findModuleByAddress(val)) count += 1;
  }
  return count;
}

function findShellcodeCandidates(stackBase: bigint | undefined, stackBytes: Uint8Array | undefined): ShellcodeHit[] {
  if (!stackBase || !stackBytes) {
    return [];
  }

  const seen = new Set<string>();
  const hits: ShellcodeHit[] = [];
  const addHit = (offset: number, reason: string) => {
    const addr = stackBase + BigInt(offset);
    const key = addr.toString();
    if (!seen.has(key)) {
      seen.add(key);
      hits.push({ address: addr, reason });
    }
  };

  // 1. NOP sled detection (>= 8 consecutive 0x90).
  for (let i = 0; i <= stackBytes.length - 8; i += 1) {
    let nopRun = 0;
    for (let j = i; j < stackBytes.length && stackBytes[j] === 0x90; j += 1) {
      nopRun += 1;
    }
    if (nopRun >= 8) {
      addHit(i, `NOP sled (${nopRun} bytes)`);
      i += nopRun;
    }
  }

  // 2. JMP/CALL/POP pattern (EB xx ... E8): the encoder stub this toolkit emits.
  for (let i = 0; i <= stackBytes.length - 6; i += 1) {
    if (stackBytes[i] !== 0xeb) continue;
    const jmpDelta: number = stackBytes[i + 1];
    if (jmpDelta < 4 || jmpDelta > 0x20) continue;
    const callSite = i + 2 + jmpDelta;
    if (callSite + 5 > stackBytes.length) continue;
    if (stackBytes[callSite] === 0xe8) {
      addHit(i, "JMP/CALL/POP decoder stub");
    }
  }

  // 3. Known shellcode prologues.
  for (let i = 0; i <= stackBytes.length - 6; i += 1) {
    for (const prologue of SHELLCODE_PROLOGUES) {
      if (matchesAt(stackBytes, i, prologue.bytes)) {
        addHit(i, prologue.label);
      }
    }
  }

  // 4. Egghunter tag: any 4-byte value repeated twice consecutively (W00TW00T pattern).
  for (let i = 0; i <= stackBytes.length - 8; i += 1) {
    if (stackBytes[i] === stackBytes[i + 4] &&
        stackBytes[i + 1] === stackBytes[i + 5] &&
        stackBytes[i + 2] === stackBytes[i + 6] &&
        stackBytes[i + 3] === stackBytes[i + 7]) {
      const d = stackBytes[i] | (stackBytes[i + 1] << 8) | (stackBytes[i + 2] << 16) | (stackBytes[i + 3] << 24);
      if (d !== 0 && d !== 0x90909090 && (d >>> 0) !== 0xffffffff) {
        const tag = String.fromCharCode(stackBytes[i], stackBytes[i + 1], stackBytes[i + 2], stackBytes[i + 3]);
        const isPrintable = [...tag].every(ch => ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) <= 0x7e);
        addHit(i, `egg tag ${isPrintable ? `"${tag}"` : `0x${(d >>> 0).toString(16)}`} x2`);
      }
    }
  }

  // 5. Entropy-based detection with negative filters.
  const WINDOW = 64;
  for (let i = 0; i <= stackBytes.length - WINDOW; i += 4) {
    const entropy = shannonEntropy(stackBytes, i, WINDOW);
    if (entropy < 4.5 || entropy > 6.5) continue;
    if (isRepeatingDwords(stackBytes, i, WINDOW)) continue;
    if (isMonotonicBytes(stackBytes, i, WINDOW)) continue;
    if (countAlignedModulePointers(stackBytes, i, WINDOW) >= 4) continue;
    addHit(i, `entropy ${entropy.toFixed(1)} bits/byte`);
  }

  hits.sort((a, b) => (a.address < b.address ? -1 : 1));

  // Prefer signature-based hits; entropy-only hits fill the remaining slots.
  const signatures = hits.filter(h => !h.reason.startsWith("entropy"));
  const entropyOnly = hits.filter(h => h.reason.startsWith("entropy"));
  const remaining = Math.max(0, 8 - signatures.length);
  return [...signatures, ...entropyOnly.slice(0, remaining)].slice(0, 8);
}

function scoreModule(module: ModuleMitigation): number {
  let score = 0;
  if (!module.system) score += 25;
  if (module.aslr === "disabled") score += 35;
  if (module.dep === "disabled") score += 10;
  if (module.safeseh === "disabled") score += 30;
  return score;
}

function scanGadgets(moduleFilter?: string): { jmp: string[]; call: string[]; ppr: string[]; pivots: string[] } {
  const fmt = (address: bigint): string => {
    const mod = findModuleByAddress(address);
    if (!mod) {
      return out.formatAddress(address, getPointerSize());
    }
    const delta = address - mod.base;
    return `${mod.name}+0x${delta.toString(16).toUpperCase()}`;
  };

  const jmpHits = scanPattern({ module: moduleFilter, executableOnly: true, maxResults: 12, chunkSize: 0x4000 }, Uint8Array.from([0xff, 0xe4])).hits;
  const callHits = scanPattern({ module: moduleFilter, executableOnly: true, maxResults: 12, chunkSize: 0x4000 }, Uint8Array.from([0xff, 0xd4])).hits;

  const pprHits: bigint[] = [];
  for (let a = 0x58; a <= 0x5f && pprHits.length < 12; a += 1) {
    for (let b = 0x58; b <= 0x5f && pprHits.length < 12; b += 1) {
      const hits = scanPattern(
        { module: moduleFilter, executableOnly: true, maxResults: Math.max(0, 12 - pprHits.length), chunkSize: 0x4000 },
        Uint8Array.from([a, b, 0xc3]),
      ).hits;
      pprHits.push(...hits);
    }
  }

  const pivotPatterns = [Uint8Array.from([0x94, 0xc3]), Uint8Array.from([0x54, 0xc3]), Uint8Array.from([0x8b, 0xe5, 0xc3])];
  const pivotHits: bigint[] = [];
  for (const pattern of pivotPatterns) {
    const hits = scanPattern(
      { module: moduleFilter, executableOnly: true, maxResults: Math.max(0, 12 - pivotHits.length), chunkSize: 0x4000 },
      pattern,
    ).hits;
    pivotHits.push(...hits);
    if (pivotHits.length >= 12) {
      break;
    }
  }

  const uniq = (values: bigint[]) => [...new Set(values.map((v) => v.toString()))].map((v) => BigInt(v));

  return {
    jmp: uniq(jmpHits).slice(0, 5).map(fmt),
    call: uniq(callHits).slice(0, 5).map(fmt),
    ppr: uniq(pprHits).slice(0, 5).map(fmt),
    pivots: uniq(pivotHits).slice(0, 5).map(fmt),
  };
}

function readSehPreview(pointerSize: 4 | 8): { overwritten: TriState; next?: bigint; handler?: bigint; warning?: string } {
  if (pointerSize !== 4) {
    return { overwritten: "unknown", warning: "SEH overwrite analysis is x86-only." };
  }

  const thread = host.currentThread as Record<string, unknown>;
  const tebCandidate = toBigInt(safeGet(thread, "Teb") ?? safeGet(thread, "TebAddress"));
  if (!tebCandidate) {
    return { overwritten: "unknown", warning: "TEB unavailable for SEH walk." };
  }

  try {
    const first = readPointer(tebCandidate, 4);
    const next = readPointer(first, 4);
    const handler = readPointer(first + BigInt(4), 4);
    const mod = findModuleByAddress(handler);
    const overwritten: TriState = mod ? "no" : "yes";
    return { overwritten, next, handler };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { overwritten: "unknown", warning: `SEH read failed: ${msg}` };
  }
}

function quickBadcharScan(bytes: Uint8Array | undefined, badchars: number[]): Array<{ byte: number; count: number; first?: number }> {
  if (!bytes) {
    return [];
  }

  return badchars.map((byte) => {
    let count = 0;
    let first: number | undefined;
    for (let i = 0; i < bytes.length; i += 1) {
      if (bytes[i] === byte) {
        count += 1;
        if (first === undefined) {
          first = i;
        }
      }
    }
    return { byte, count, first };
  });
}

export function createTriageCommand(): Command {
  return {
    name: "triage",
    description: "Fast crash triage for exploit-development workflows.",
    usage: "dx @$osed().triage({ patternLength: 10000, badchars: [0,10,13], module: 'essfunc' })",
    examples: ["dx @$osed().triage()", "dx @$osed().triage({ module: 'vuln' })"],
    schema: {
      patternLength: { type: "number", min: 256, max: 100000, default: 10000 },
      badchars: { type: "array", elementType: "number", default: [0, 10, 13] },
      module: { type: "string" },
      stackBytes: { type: "number", min: 128, max: 4096, default: 1024 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const regs = readRegisters(pointerSize);
      const patternLength = options.patternLength as number;
      const stackBytesToRead = options.stackBytes as number;
      const badchars = ((options.badchars as number[]) ?? [0, 10, 13]).map((v) => v & 0xff);
      const moduleFilter = options.module as string | undefined;

      const patternOffset = findOffset(regs.ip, patternLength);
      const seh = readSehPreview(pointerSize);
      const stack = scanStack(regs.sp, stackBytesToRead);
      const shellcode = findShellcodeCandidates(stack.base, stack.bytes);
      const badcharStats = quickBadcharScan(stack.bytes, badchars);

      const modules = listModulesWithMitigations(moduleFilter)
        .map((module) => ({
          module: module.name,
          score: scoreModule(module),
          aslr: module.aslr,
          dep: module.dep,
          safeseh: module.safeseh,
          system: module.system,
        }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 6);

      const gadgets = scanGadgets(moduleFilter);

      const eipControlled = patternOffset ? "yes" : "no";
      const badSp = stack.bytes ? "no" : "yes";

      out.section("CONTROL");
      out.print(`EIP/RIP controlled: ${eipControlled}`);
      out.print(`Offset: ${patternOffset ? patternOffset.offset : "n/a"}`);
      out.print(`Pattern: ${patternOffset ? patternOffset.kind : "n/a"}`);

      out.section("SEH");
      out.print(`Overwritten: ${seh.overwritten}`);
      out.print(`Next SEH: ${seh.next !== undefined ? out.formatAddress(seh.next, 4) : "n/a"}`);
      out.print(`Handler: ${seh.handler !== undefined ? out.formatAddress(seh.handler, 4) : "n/a"}`);

      out.section("STACK");
      out.print(`${regs.spName ?? "SP"}: ${regs.sp !== undefined ? out.formatAddress(regs.sp, pointerSize) : "n/a"}`);
      out.print(`Bad stack pointer: ${badSp}`);
      out.print(`SP points into cyclic pattern: ${stack.bytes && regs.sp ? (findOffset(regs.sp, patternLength) ? "yes" : "no") : "unknown"}`);
      if (shellcode.length > 0) {
        out.print("Shellcode candidates:");
        for (const candidate of shellcode) {
          out.print(`  ${out.formatAddress(candidate.address, pointerSize)}  ${candidate.reason}`);
        }
      } else {
        out.print("Shellcode candidates: none");
      }

      out.section("GADGETS");
      out.print("JMP ESP/RSP:");
      for (const line of gadgets.jmp) out.print(`  ${line}`);
      out.print("CALL ESP/RSP:");
      for (const line of gadgets.call) out.print(`  ${line}`);
      out.print("POP POP RET:");
      for (const line of gadgets.ppr) out.print(`  ${line}`);
      out.print("Stack pivots:");
      for (const line of gadgets.pivots) out.print(`  ${line}`);

      out.section("CONTEXT");
      out.print(`Exception code: ${regs.exceptionCode !== undefined ? out.formatAddress(regs.exceptionCode, 4) : "n/a"}`);
      out.print(`${regs.ipName ?? "IP"}: ${regs.ip !== undefined ? out.formatAddress(regs.ip, pointerSize) : "n/a"}`);

      out.section("MODULE SCORE");
      out.table(
        [
          { key: "module", header: "Module", width: 20 },
          { key: "score", header: "Score", width: 6 },
          { key: "aslr", header: "ASLR", width: 8 },
          { key: "dep", header: "DEP", width: 8 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "system", header: "System", width: 8 },
        ],
        modules.map((item) => ({
          module: item.module,
          score: `${item.score}`,
          aslr: item.aslr,
          dep: item.dep,
          safeseh: item.safeseh,
          system: item.system ? "yes" : "no",
        })),
      );

      out.section("BADCHAR QUICK SCAN");
      out.table(
        [
          { key: "byte", header: "Byte", width: 8 },
          { key: "count", header: "Count", width: 6 },
          { key: "first", header: "FirstOff", width: 8 },
        ],
        badcharStats.map((entry) => ({
          byte: out.formatHexByte(entry.byte),
          count: `${entry.count}`,
          first: entry.first !== undefined ? `${entry.first}` : "n/a",
        })),
      );

      const warnings: string[] = [];
      if (stack.warning) warnings.push(stack.warning);
      if (seh.warning) warnings.push(seh.warning);

      const findings = [
        {
          control: {
            ipControlled: eipControlled === "yes",
            offset: patternOffset?.offset,
            pattern: patternOffset?.kind,
            ip: regs.ip,
            ipName: regs.ipName,
          },
          seh,
          stack: {
            sp: regs.sp,
            spName: regs.spName,
            badPointer: badSp === "yes",
            shellcodeCandidates: shellcode.map(h => ({ address: h.address, reason: h.reason })),
          },
          gadgets,
          modules,
          badchars: badcharStats,
          exception: regs.exceptionCode,
        },
      ];

      return {
        command: "triage",
        args: options,
        success: true,
        findings,
        warnings,
        errors: [],
      };
    },
  };
}
