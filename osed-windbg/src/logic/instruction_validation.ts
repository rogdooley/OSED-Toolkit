import { ValidationFlags } from "../core/registry";

export type GadgetPattern = {
  name: string;
  bytes: number[];
  mnemonic: string;
};

export type InstructionValidationResult = {
  flags: ValidationFlags;
  mnemonic?: string;
};

const KNOWN_PATTERNS: GadgetPattern[] = [
  { name: "pop_eax_ret", bytes: [0x58, 0xc3], mnemonic: "pop eax ; ret" },
  { name: "pop_ecx_ret", bytes: [0x59, 0xc3], mnemonic: "pop ecx ; ret" },
  { name: "pop_edx_ret", bytes: [0x5a, 0xc3], mnemonic: "pop edx ; ret" },
  { name: "pop_ebx_ret", bytes: [0x5b, 0xc3], mnemonic: "pop ebx ; ret" },
  { name: "push_esp_ret", bytes: [0x54, 0xc3], mnemonic: "push esp ; ret" },
  { name: "xchg_eax_esp_ret", bytes: [0x94, 0xc3], mnemonic: "xchg eax, esp ; ret" },
];

const POP_REGS: Array<{ code: number; name: string }> = [
  { code: 0x58, name: "eax" },
  { code: 0x59, name: "ecx" },
  { code: 0x5a, name: "edx" },
  { code: 0x5b, name: "ebx" },
  { code: 0x5c, name: "esp" },
  { code: 0x5d, name: "ebp" },
  { code: 0x5e, name: "esi" },
  { code: 0x5f, name: "edi" },
];

function buildPprPatterns(): GadgetPattern[] {
  const patterns: GadgetPattern[] = [];
  for (const first of POP_REGS) {
    for (const second of POP_REGS) {
      patterns.push({
        name: `pop_${first.name}_pop_${second.name}_ret`,
        bytes: [first.code, second.code, 0xc3],
        mnemonic: `pop ${first.name} ; pop ${second.name} ; ret`,
      });
    }
  }
  return patterns;
}

const ALL_PATTERNS: GadgetPattern[] = [...KNOWN_PATTERNS, ...buildPprPatterns()];

function sameBytes(left: Uint8Array, right: number[]): boolean {
  if (left.length !== right.length) {
    return false;
  }

  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) {
      return false;
    }
  }

  return true;
}

export function knownPatterns(): GadgetPattern[] {
  return ALL_PATTERNS;
}

export function validateInstructionCandidate(
  candidateBytes: Uint8Array,
  executable: boolean,
  moduleBacked: boolean,
): InstructionValidationResult {
  const matched = ALL_PATTERNS.find((pattern) => sameBytes(candidateBytes, pattern.bytes));

  return {
    flags: {
      executable,
      moduleBacked,
      decoded: matched !== undefined,
      mnemonicMatch: matched !== undefined,
      badcharSafe: true,
    },
    mnemonic: matched?.mnemonic,
  };
}
