import { getPointerSize, readMemory, readUint16LE, readUint32LE, readPointer } from "../core/memory";
import { formatAddress } from "../core/output";

type ModuleInfo = {
  name: string;
  path: string;
  base: bigint;
  end: bigint;
  size: bigint;
};

type LookupResult =
  | { kind: "ok"; module: ModuleInfo }
  | { kind: "ambiguous"; candidates: ModuleInfo[] }
  | { kind: "not_found"; name: string };

type PeHeaders = {
  dosHeader: bigint;
  eLfanew: number;
  ntHeader: bigint;
  machine: number;
  machineName: string;
  entryPointRva: number;
  entryPointVa: bigint;
  imageBase: bigint;
  sizeOfImage: number;
  optionalHeaderMagic: number;
  exportDirectoryRva: number;
  exportDirectoryVa: bigint;
  exportDirectorySize: number;
};

type ExportEntry = {
  ordinal: number;
  rva: number;
  va: bigint;
  name: string;
};

interface HashProvider {
  readonly algorithm: string;
  readonly aliases?: string[];
  readonly description: string;
  hash(text: string): number;
}

class MetasploitRor13Provider implements HashProvider {
  public readonly algorithm = "metasploit_ror13";
  public readonly aliases = ["ror13", "msf_ror13"];
  public readonly description = "Classic Metasploit-style API hash: ROR 13 then add byte.";

  private ror32(value: number, bits: number): number {
    const shift = bits & 31;
    return ((value >>> shift) | (value << (32 - shift))) >>> 0;
  }

  public hash(text: string): number {
    let hash = 0;
    for (let i = 0; i < text.length; i += 1) {
      hash = this.ror32(hash, 13);
      hash = (hash + (text.charCodeAt(i) & 0xff)) >>> 0;
    }
    return hash >>> 0;
  }
}

class HashResolver {
  private readonly providers: Map<string, HashProvider>;
  private readonly canonicalProviders: HashProvider[];
  private readonly defaultAlias = "ror13";

  public constructor(providers?: HashProvider[]) {
    const configured = providers ?? [
      new MetasploitRor13Provider(),
      new Crc32Provider(),
      new Rol13AddProvider(),
      new Rol7AddProvider(),
    ];
    this.canonicalProviders = configured;
    this.providers = new Map<string, HashProvider>();
    for (const provider of configured) {
      this.providers.set(provider.algorithm.toLowerCase(), provider);
      for (const alias of provider.aliases ?? []) {
        this.providers.set(alias.toLowerCase(), provider);
      }
    }
  }

  public compute(exportsList: ExportEntry[], algorithm?: string): Array<Record<string, string>> {
    const provider = this.resolveProvider(algorithm);
    if (!provider) {
      throw new Error(`Unknown hash algorithm "${algorithm}". Supported: ${this.supportedAlgorithms().join(", ")}.`);
    }

    const label = this.displayName(provider);
    return exportsList
      .filter((entry) => entry.name.length > 0)
      .map((entry) => ({
        Algorithm: label,
        Hash: `0x${provider.hash(entry.name).toString(16).toUpperCase().padStart(8, "0")}`,
        Name: entry.name,
        Address: toDmlAddress(entry.va, "u"),
      }))
      .sort((a, b) => a.Name.localeCompare(b.Name));
  }

  public hashValue(text: string, algorithm?: string): Record<string, string> {
    const provider = this.resolveProvider(algorithm);
    if (!provider) {
      throw new Error(`Unknown hash algorithm "${algorithm}". Supported: ${this.supportedAlgorithms().join(", ")}.`);
    }
    return {
      Input: text,
      Algorithm: this.displayName(provider),
      Hash: `0x${provider.hash(text).toString(16).toUpperCase().padStart(8, "0")}`,
    };
  }

  public listAlgorithms(): Array<Record<string, string>> {
    const defaultProvider = this.resolveProvider(this.defaultAlias);
    return this.canonicalProviders
      .map((provider) => ({
        Algorithm: provider.algorithm,
        Aliases: (provider.aliases ?? []).join(", "),
        Description: provider.description,
        Default: provider === defaultProvider ? "yes" : "no",
      }))
      .sort((a, b) => a.Algorithm.localeCompare(b.Algorithm));
  }

  public supportedAlgorithms(): string[] {
    return Array.from(this.providers.keys()).sort();
  }

  private resolveProvider(algorithm?: string): HashProvider | undefined {
    const selected = (algorithm ?? this.defaultAlias).trim().toLowerCase();
    return this.providers.get(selected);
  }

  private displayName(provider: HashProvider): string {
    return provider.aliases && provider.aliases.length > 0 ? provider.aliases[0].toUpperCase() : provider.algorithm;
  }
}

class Crc32Provider implements HashProvider {
  public readonly algorithm = "crc32";
  public readonly description = "CRC32 (IEEE polynomial 0xEDB88320) over ASCII bytes.";
  private readonly table: number[];

  public constructor() {
    this.table = this.buildTable();
  }

  public hash(text: string): number {
    let crc = 0xffffffff;
    for (let i = 0; i < text.length; i += 1) {
      const byte = text.charCodeAt(i) & 0xff;
      const index = (crc ^ byte) & 0xff;
      crc = (crc >>> 8) ^ this.table[index];
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  private buildTable(): number[] {
    const table: number[] = [];
    for (let i = 0; i < 256; i += 1) {
      let value = i;
      for (let bit = 0; bit < 8; bit += 1) {
        if ((value & 1) === 1) {
          value = (value >>> 1) ^ 0xedb88320;
        } else {
          value >>>= 1;
        }
      }
      table.push(value >>> 0);
    }
    return table;
  }
}

class Rol13AddProvider implements HashProvider {
  public readonly algorithm = "rol13_add";
  public readonly aliases = ["rol13"];
  public readonly description = "Rotate-left by 13 then add byte (32-bit accumulator).";

  private rol32(value: number, bits: number): number {
    const shift = bits & 31;
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
  }

  public hash(text: string): number {
    let hash = 0;
    for (let i = 0; i < text.length; i += 1) {
      hash = this.rol32(hash, 13);
      hash = (hash + (text.charCodeAt(i) & 0xff)) >>> 0;
    }
    return hash >>> 0;
  }
}

class Rol7AddProvider implements HashProvider {
  public readonly algorithm = "rol7_add";
  public readonly aliases = ["rol7"];
  public readonly description = "Rotate-left by 7 then add byte (32-bit accumulator).";

  private rol32(value: number, bits: number): number {
    const shift = bits & 31;
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
  }

  public hash(text: string): number {
    let hash = 0;
    for (let i = 0; i < text.length; i += 1) {
      hash = this.rol32(hash, 7);
      hash = (hash + (text.charCodeAt(i) & 0xff)) >>> 0;
    }
    return hash >>> 0;
  }
}

class PEParser {
  private readonly pointerSize: 4 | 8;

  public constructor(pointerSize: 4 | 8) {
    this.pointerSize = pointerSize;
  }

  public parseHeaders(module: ModuleInfo): PeHeaders {
    const base = module.base;
    const mz = readUint16LE(base);
    if (mz !== 0x5a4d) {
      throw new Error(`Invalid DOS header for ${module.name}.`);
    }

    const eLfanew = readUint32LE(base + BigInt(0x3c));
    const ntHeader = base + BigInt(eLfanew);
    const signature = readUint32LE(ntHeader);
    if (signature !== 0x4550) {
      throw new Error(`Invalid NT header signature for ${module.name}.`);
    }

    const machine = readUint16LE(ntHeader + BigInt(0x4));
    const optionalHeader = ntHeader + BigInt(0x18);
    const optionalHeaderMagic = readUint16LE(optionalHeader);
    const isPe32Plus = optionalHeaderMagic === 0x20b;
    if (!isPe32Plus && optionalHeaderMagic !== 0x10b) {
      throw new Error(`Unsupported optional header magic 0x${optionalHeaderMagic.toString(16)}.`);
    }

    const entryPointRva = readUint32LE(optionalHeader + BigInt(0x10));
    const imageBase = isPe32Plus
      ? readPointer(optionalHeader + BigInt(0x18), 8)
      : BigInt(readUint32LE(optionalHeader + BigInt(0x1c)) >>> 0);
    const sizeOfImage = readUint32LE(optionalHeader + BigInt(0x38));

    const dataDirectoryOffset = optionalHeader + BigInt(isPe32Plus ? 0x70 : 0x60);
    const exportDirectoryRva = readUint32LE(dataDirectoryOffset);
    const exportDirectorySize = readUint32LE(dataDirectoryOffset + BigInt(0x4));

    return {
      dosHeader: base,
      eLfanew,
      ntHeader,
      machine,
      machineName: machineToString(machine),
      entryPointRva,
      entryPointVa: base + BigInt(entryPointRva >>> 0),
      imageBase,
      sizeOfImage,
      optionalHeaderMagic,
      exportDirectoryRva,
      exportDirectoryVa: base + BigInt(exportDirectoryRva >>> 0),
      exportDirectorySize,
    };
  }

  public parseExports(module: ModuleInfo): ExportEntry[] {
    const headers = this.parseHeaders(module);
    if (headers.exportDirectoryRva === 0 || headers.exportDirectorySize === 0) {
      return [];
    }

    const exportDir = module.base + BigInt(headers.exportDirectoryRva >>> 0);
    const ordinalBase = readUint32LE(exportDir + BigInt(0x10));
    const numberOfFunctions = readUint32LE(exportDir + BigInt(0x14));
    const numberOfNames = readUint32LE(exportDir + BigInt(0x18));
    const addressOfFunctions = readUint32LE(exportDir + BigInt(0x1c));
    const addressOfNames = readUint32LE(exportDir + BigInt(0x20));
    const addressOfNameOrdinals = readUint32LE(exportDir + BigInt(0x24));

    if (numberOfFunctions === 0 || addressOfFunctions === 0) {
      return [];
    }

    const functionsVa = module.base + BigInt(addressOfFunctions >>> 0);
    const namesVa = module.base + BigInt(addressOfNames >>> 0);
    const ordinalsVa = module.base + BigInt(addressOfNameOrdinals >>> 0);

    const namesByIndex = new Map<number, string>();

    for (let i = 0; i < numberOfNames; i += 1) {
      const nameRva = readUint32LE(namesVa + BigInt(i * 4));
      const ordinalIndex = readUint16LE(ordinalsVa + BigInt(i * 2));
      const nameAddress = module.base + BigInt(nameRva >>> 0);
      namesByIndex.set(ordinalIndex, readAsciiString(nameAddress, 512));
    }

    const entries: ExportEntry[] = [];
    for (let index = 0; index < numberOfFunctions; index += 1) {
      const rva = readUint32LE(functionsVa + BigInt(index * 4));
      const va = module.base + BigInt(rva >>> 0);
      const ordinal = ordinalBase + index;
      entries.push({
        ordinal,
        rva,
        va,
        name: namesByIndex.get(index) ?? "",
      });
    }

    return entries;
  }

  public formatHeaderRows(module: ModuleInfo): Array<Record<string, string>> {
    const headers = this.parseHeaders(module);
    return [
      { Field: "Base", Value: toDmlAddress(module.base, "db") },
      { Field: "DOS Header", Value: toDmlAddress(headers.dosHeader, "db") },
      { Field: "e_lfanew", Value: `0x${headers.eLfanew.toString(16).toUpperCase()}` },
      { Field: "NT Header", Value: toDmlAddress(headers.ntHeader, "db") },
      { Field: "Machine", Value: `${headers.machineName} (0x${headers.machine.toString(16).toUpperCase()})` },
      { Field: "EntryPoint", Value: `${toDmlAddress(headers.entryPointVa, "u")} (RVA 0x${headers.entryPointRva.toString(16).toUpperCase()})` },
      { Field: "ImageBase", Value: formatAddress(headers.imageBase, this.pointerSize) },
      { Field: "SizeOfImage", Value: `0x${headers.sizeOfImage.toString(16).toUpperCase()}` },
      { Field: "ExportDir RVA", Value: `0x${headers.exportDirectoryRva.toString(16).toUpperCase()}` },
      { Field: "ExportDir VA", Value: toDmlAddress(headers.exportDirectoryVa, "db") },
    ];
  }
}

class ExportResolver {
  private readonly parser: PEParser;

  public constructor(parser: PEParser) {
    this.parser = parser;
  }

  public enumerate(module: ModuleInfo, filter?: string): Array<Record<string, string>> {
    const entries = this.parser.parseExports(module);
    const needle = normalizeNeedle(filter);
    return entries
      .filter((entry) => {
        if (!needle) {
          return true;
        }
        return entry.name.toLowerCase().includes(needle);
      })
      .sort((a, b) => {
        const left = a.name || `~${a.ordinal.toString(16)}`;
        const right = b.name || `~${b.ordinal.toString(16)}`;
        return left.localeCompare(right);
      })
      .map((entry) => ({
        Ordinal: entry.ordinal.toString(),
        RVA: `0x${entry.rva.toString(16).toUpperCase().padStart(8, "0")}`,
        VA: toDmlAddress(entry.va, "u"),
        Name: entry.name || "<unnamed>",
      }));
  }

  public resolve(module: ModuleInfo, symbol: string): ExportEntry | undefined {
    const needle = symbol.trim().toLowerCase();
    if (!needle) {
      return undefined;
    }
    return this.parser.parseExports(module).find((entry) => entry.name.toLowerCase() === needle);
  }

  public getExports(module: ModuleInfo): ExportEntry[] {
    return this.parser.parseExports(module);
  }
}

class ShellcodeHelper {
  private readonly pointerSize: 4 | 8;
  private readonly parser: PEParser;
  private readonly exportResolver: ExportResolver;
  private readonly hashResolver: HashResolver;

  public constructor() {
    this.pointerSize = getPointerSize();
    this.parser = new PEParser(this.pointerSize);
    this.exportResolver = new ExportResolver(this.parser);
    this.hashResolver = new HashResolver();
  }

  public peb(): Array<Record<string, string>> {
    const pebAddress = this.getPebAddress();
    if (!pebAddress) {
      return this.errorRows("Unable to resolve PEB in current context.");
    }

    try {
      const ldrOffset = this.pointerSize === 8 ? 0x18 : 0x0c;
      const processParametersOffset = this.pointerSize === 8 ? 0x20 : 0x10;
      const imageBaseOffset = this.pointerSize === 8 ? 0x10 : 0x08;

      const ldr = readPointer(pebAddress + BigInt(ldrOffset), this.pointerSize);
      const processParameters = readPointer(pebAddress + BigInt(processParametersOffset), this.pointerSize);
      const imageBase = readPointer(pebAddress + BigInt(imageBaseOffset), this.pointerSize);
      const beingDebugged = readMemory(pebAddress + BigInt(0x2), 1)[0] !== 0;

      return [
        { Field: "PEB", Value: toDmlAddress(pebAddress, "db") },
        { Field: "Ldr", Value: toDmlAddress(ldr, "db") },
        { Field: "ProcessParameters", Value: toDmlAddress(processParameters, "db") },
        { Field: "BeingDebugged", Value: beingDebugged ? "true" : "false" },
        { Field: "ImageBase", Value: toDmlAddress(imageBase, "db") },
      ];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public modules(): Array<Record<string, string>> {
    return this.readModules().map((module) => ({
      Base: toDmlAddress(module.base, "db"),
      End: toDmlAddress(module.end, "db"),
      Size: `0x${module.size.toString(16).toUpperCase()}`,
      Name: module.name,
      Path: module.path,
    }));
  }

  public base(name: string): Array<Record<string, string>> {
    const lookup = this.findModule(name);
    if (lookup.kind === "ok") {
      return [{ Module: lookup.module.name, Base: toDmlAddress(lookup.module.base, "db") }];
    }
    if (lookup.kind === "ambiguous") {
      return this.moduleCandidatesRows(lookup.candidates);
    }
    return this.errorRows(`No module matches "${name}".`);
  }

  public pe(name: string): Array<Record<string, string>> {
    const lookup = this.findModule(name);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    try {
      return this.parser.formatHeaderRows(lookup.module);
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public exports(name: string, filter?: string): Array<Record<string, string>> {
    const lookup = this.findModule(name);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    try {
      const rows = this.exportResolver.enumerate(lookup.module, filter);
      if (rows.length === 0) {
        return this.errorRows("No exports matched the requested filter.");
      }
      return rows;
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public resolve(moduleName: string, symbol: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    const entry = this.exportResolver.resolve(lookup.module, symbol);
    if (!entry) {
      return this.errorRows(`Symbol "${symbol}" was not found in ${lookup.module.name}.`);
    }

    return [
      {
        Module: lookup.module.name,
        Symbol: `${entry.name} (${lookup.module.name}!${entry.name})`,
        Address: toDmlAddress(entry.va, "u"),
      },
    ];
  }

  public hashes(moduleName: string, algorithm?: string): Array<Record<string, string>> {
    const lookup = this.findModule(moduleName);
    if (lookup.kind !== "ok") {
      return this.lookupFailureRows(lookup);
    }

    try {
      const exportsList = this.exportResolver.getExports(lookup.module);
      const rows = this.hashResolver.compute(exportsList, algorithm);
      if (rows.length === 0) {
        return this.errorRows("No named exports were found to hash.");
      }
      return rows;
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public hash(name: string, algorithm = "ROR13"): Array<Record<string, string>> {
    const input = name.trim();
    if (!input) {
      return this.errorRows("Input string is required.");
    }
    try {
      return [this.hashResolver.hashValue(input, algorithm)];
    } catch (error) {
      return this.errorRows(formatError(error));
    }
  }

  public algorithms(): Array<Record<string, string>> {
    return this.hashResolver.listAlgorithms();
  }

  private findModule(name: string): LookupResult {
    const needle = normalizeNeedle(name);
    if (!needle) {
      return { kind: "not_found", name };
    }

    const modules = this.readModules();
    const scored = modules
      .map((module) => {
        const basename = module.name.toLowerCase();
        const basenameNoExt = basename.endsWith(".dll") ? basename.slice(0, -4) : basename;
        const fullPath = module.path.toLowerCase();

        if (basename === needle || basenameNoExt === needle) {
          return { module, score: 0 };
        }
        if (basename.startsWith(needle) || basenameNoExt.startsWith(needle)) {
          return { module, score: 1 };
        }
        if (basename.includes(needle) || basenameNoExt.includes(needle)) {
          return { module, score: 2 };
        }
        if (fullPath.includes(needle)) {
          return { module, score: 3 };
        }
        return undefined;
      })
      .filter((entry): entry is { module: ModuleInfo; score: number } => entry !== undefined);

    if (scored.length === 0) {
      return { kind: "not_found", name };
    }

    const bestScore = Math.min(...scored.map((entry) => entry.score));
    const candidates = scored
      .filter((entry) => entry.score === bestScore)
      .map((entry) => entry.module)
      .sort((a, b) => (a.base < b.base ? -1 : 1));

    if (candidates.length === 1) {
      return { kind: "ok", module: candidates[0] };
    }
    return { kind: "ambiguous", candidates };
  }

  private getPebAddress(): bigint | undefined {
    const hostAny = host as unknown as {
      namespace?: {
        Debugger?: {
          State?: {
            PseudoRegisters?: {
              General?: {
                peb?: unknown;
              };
            };
          };
        };
      };
      currentProcess?: {
        Environment?: {
          EnvironmentBlock?: unknown;
        };
      };
    };

    const fromPseudo = tryToBigInt(hostAny.namespace?.Debugger?.State?.PseudoRegisters?.General?.peb);
    if (fromPseudo && fromPseudo !== BigInt(0)) {
      return fromPseudo;
    }

    const fromProcess = tryToBigInt(hostAny.currentProcess?.Environment?.EnvironmentBlock);
    if (fromProcess && fromProcess !== BigInt(0)) {
      return fromProcess;
    }

    return undefined;
  }

  private readModules(): ModuleInfo[] {
    const hostAny = host as unknown as {
      currentProcess?: {
        Modules?: unknown;
      };
    };
    const source = hostAny.currentProcess?.Modules;
    const items = toArray(source);
    return items
      .map((entry) => {
        const moduleAny = entry as {
          Name?: string;
          Path?: string;
          BaseAddress?: unknown;
          Base?: unknown;
          Address?: unknown;
          EndAddress?: unknown;
          Size?: unknown;
          Length?: unknown;
        };
        const name = moduleAny.Name ?? "<unknown>";
        const path = moduleAny.Path ?? name;
        const base = tryToBigInt(moduleAny.BaseAddress ?? moduleAny.Base ?? moduleAny.Address) ?? BigInt(0);
        let end = tryToBigInt(moduleAny.EndAddress);
        const sizeFromModule = tryToBigInt(moduleAny.Size ?? moduleAny.Length);
        if (!end && sizeFromModule && sizeFromModule > BigInt(0)) {
          end = base + sizeFromModule;
        }
        if (!end) {
          end = base;
        }
        const size = end > base ? end - base : BigInt(0);

        return {
          name,
          path,
          base,
          end,
          size,
        };
      })
      .filter((module) => module.base !== BigInt(0))
      .sort((a, b) => (a.base < b.base ? -1 : 1));
  }

  private moduleCandidatesRows(candidates: ModuleInfo[]): Array<Record<string, string>> {
    return candidates.map((module) => ({
      Base: toDmlAddress(module.base, "db"),
      End: toDmlAddress(module.end, "db"),
      Name: module.name,
      Path: module.path,
    }));
  }

  private lookupFailureRows(lookup: LookupResult): Array<Record<string, string>> {
    if (lookup.kind === "ambiguous") {
      return this.moduleCandidatesRows(lookup.candidates);
    }
    return this.errorRows(`No module matches "${lookup.name}".`);
  }

  private errorRows(message: string): Array<Record<string, string>> {
    return [{ Error: message }];
  }
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

function tryToBigInt(value: unknown): bigint | undefined {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return BigInt(Math.max(0, Math.trunc(value)));
  }
  if (typeof value === "string") {
    const text = value.trim();
    if (/^0x[0-9a-f]+$/i.test(text)) {
      return BigInt(text);
    }
    if (/^[0-9a-f]+$/i.test(text)) {
      return BigInt(`0x${text}`);
    }
    if (/^[0-9]+$/.test(text)) {
      return BigInt(text);
    }
    return undefined;
  }
  if (!value || typeof value !== "object") {
    return undefined;
  }

  const addressed = value as { address?: unknown; Address?: unknown };
  const fromAddress = tryToBigInt(addressed.address ?? addressed.Address);
  if (fromAddress !== undefined) {
    return fromAddress;
  }

  const valueOf = (value as { valueOf?: () => unknown }).valueOf;
  if (typeof valueOf === "function") {
    const unwrapped = valueOf.call(value);
    if (unwrapped !== value) {
      const parsed = tryToBigInt(unwrapped);
      if (parsed !== undefined) {
        return parsed;
      }
    }
  }

  const asString = (value as { toString?: () => string }).toString;
  if (typeof asString === "function") {
    return tryToBigInt(asString.call(value));
  }

  return undefined;
}

function readAsciiString(address: bigint, maxLength: number): string {
  const bytes = readMemory(address, maxLength);
  const chars: string[] = [];
  for (let i = 0; i < bytes.length; i += 1) {
    const ch = bytes[i];
    if (ch === 0) {
      break;
    }
    chars.push(String.fromCharCode(ch));
  }
  return chars.join("");
}

function toDmlAddress(address: bigint, command: string): string {
  const hex = `0x${address.toString(16).toUpperCase()}`;
  return `<link cmd="${command} ${hex}">${hex}</link>`;
}

function machineToString(machine: number): string {
  switch (machine) {
    case 0x014c:
      return "x86";
    case 0x8664:
      return "x64";
    default:
      return "unknown";
  }
}

function normalizeNeedle(value?: string): string {
  if (!value) {
    return "";
  }
  return value.trim().toLowerCase();
}

function formatError(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return String(error);
}

export function createShellcodeNamespace(): {
  peb: () => Array<Record<string, string>>;
  modules: () => Array<Record<string, string>>;
  base: (name: string) => Array<Record<string, string>>;
  pe: (name: string) => Array<Record<string, string>>;
  exports: (name: string, filter?: string) => Array<Record<string, string>>;
  resolve: (module: string, symbol: string) => Array<Record<string, string>>;
  hashes: (module: string, algorithm?: string) => Array<Record<string, string>>;
  hash: (name: string, algorithm?: string) => Array<Record<string, string>>;
  algorithms: () => Array<Record<string, string>>;
} {
  const helper = new ShellcodeHelper();
  return {
    peb: () => helper.peb(),
    modules: () => helper.modules(),
    base: (name: string) => helper.base(name),
    pe: (name: string) => helper.pe(name),
    exports: (name: string, filter?: string) => helper.exports(name, filter),
    resolve: (module: string, symbol: string) => helper.resolve(module, symbol),
    hashes: (module: string, algorithm?: string) => helper.hashes(module, algorithm),
    hash: (name: string, algorithm?: string) => helper.hash(name, algorithm),
    algorithms: () => helper.algorithms(),
  };
}
