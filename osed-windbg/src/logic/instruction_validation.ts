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
  { name: "pop_eax_pop_eax_ret", bytes: [0x58, 0x58, 0xc3], mnemonic: "pop eax ; pop eax ; ret" },
  { name: "pop_ecx_pop_ecx_ret", bytes: [0x59, 0x59, 0xc3], mnemonic: "pop ecx ; pop ecx ; ret" },
  { name: "pop_edx_pop_edx_ret", bytes: [0x5a, 0x5a, 0xc3], mnemonic: "pop edx ; pop edx ; ret" },
  { name: "pop_ebx_pop_ebx_ret", bytes: [0x5b, 0x5b, 0xc3], mnemonic: "pop ebx ; pop ebx ; ret" },
  { name: "pop_ebp_pop_ebp_ret", bytes: [0x5d, 0x5d, 0xc3], mnemonic: "pop ebp ; pop ebp ; ret" },
  { name: "pop_esi_pop_esi_ret", bytes: [0x5e, 0x5e, 0xc3], mnemonic: "pop esi ; pop esi ; ret" },
  { name: "pop_edi_pop_edi_ret", bytes: [0x5f, 0x5f, 0xc3], mnemonic: "pop edi ; pop edi ; ret" },
  { name: "pop_esi_pop_edi_ret", bytes: [0x5e, 0x5f, 0xc3], mnemonic: "pop esi ; pop edi ; ret" },
  { name: "pop_edi_pop_esi_ret", bytes: [0x5f, 0x5e, 0xc3], mnemonic: "pop edi ; pop esi ; ret" },
  { name: "push_esp_ret", bytes: [0x54, 0xc3], mnemonic: "push esp ; ret" },
  { name: "xchg_eax_esp_ret", bytes: [0x94, 0xc3], mnemonic: "xchg eax, esp ; ret" },
];

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
  return KNOWN_PATTERNS;
}

export function validateInstructionCandidate(
  candidateBytes: Uint8Array,
  executable: boolean,
  moduleBacked: boolean,
): InstructionValidationResult {
  const matched = KNOWN_PATTERNS.find((pattern) => sameBytes(candidateBytes, pattern.bytes));

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
