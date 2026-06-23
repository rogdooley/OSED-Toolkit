/*
Shellcode helper usage:
dx @$osed().sc.peb()
dx @$osed().sc.modules()
dx @$osed().sc.base("kernel")
dx @$osed().sc.exports("kernel32")
dx @$osed().sc.resolve("kernel32","WinExec")
dx @$osed().sc.hashes("kernel32")
dx @$osed().sc.hashes("kernel32","crc32")
dx @$osed().sc.hash("WinExec","ROR13")
dx @$osed().sc.hashresolve("kernel32",0x7c0dfcaa)
dx @$osed().sc.algorithms()
dx @$osed().sc.exportdir("kernel32")
dx @$osed().sc.export("kernel32","GetProcAddress")
dx @$osed().sc.exportat("kernel32",842)
dx @$osed().sc.exportwalk("kernel32","GetProcAddress")
dx @$osed().sc.exportwalk("kernel32","GetProcAddress",true)
dx @$osed().sc.iat()
dx @$osed().sc.iat("app.exe")
dx @$osed().sc.iat_find("VirtualAlloc")
dx @$osed().sc.iat_ptr("app.exe","VirtualAlloc")
*/

import { Command, CommandRegistry, CommandResult } from "./core/registry";
import { createPatternCommands } from "./commands/pattern";
import { createBadcharsCommand } from "./commands/badchars";
import { createEgghunterCommand } from "./commands/egghunter";
import { createSehCommand } from "./commands/seh";
import { createModulesCommand } from "./commands/modules";
import { createRopCommands } from "./commands/rop";
import { createPivotCommand } from "./commands/pivot";
import { createHelpCommand } from "./commands/help";
import { createReloadCommand } from "./commands/reload";
import { createSehPprCommand } from "./commands/seh_ppr";
import { createExploitCommand } from "./commands/exploit";
import { createTriageCommand } from "./commands/triage";
import { createEncodeCommand } from "./commands/encode";
import { createNopCommand } from "./commands/nop";
import { createRopTemplateCommand } from "./commands/rop_template";
import { createShellcodeNamespace } from "./shellcode";

type OsedApi = {
  [name: string]: unknown;
};

const registry = new CommandRegistry();
let osed: OsedApi = {};
let lastResult: CommandResult | undefined;

function getGlobalObject(): Record<string, unknown> | undefined {
  if (typeof globalThis !== "undefined") {
    return globalThis as unknown as Record<string, unknown>;
  }
  if (typeof self !== "undefined") {
    return self as unknown as Record<string, unknown>;
  }
  return undefined;
}

function publishOsed(): void {
  const globalObject = getGlobalObject();
  if (globalObject) {
    globalObject.osed = osed;
  }
}

function registerAll(): void {
  const commands: Command[] = [
    ...createPatternCommands(),
    createBadcharsCommand(),
    createEgghunterCommand(),
    createSehCommand(),
    createModulesCommand(),
    ...createRopCommands(),
    createPivotCommand(),
    createSehPprCommand(),
    createTriageCommand(),
    createEncodeCommand(),
    createNopCommand(),
    createRopTemplateCommand(),
    createExploitCommand(),
    createHelpCommand(registry),
    createReloadCommand(registry),
  ];

  for (const command of commands) {
    registry.register(command);
  }
}

function bindApi(): OsedApi {
  const api: OsedApi = {};
  const invoke = (commandName: string, args: unknown[]) => {
    const result = registry.execute(commandName, normalizeInvocation(commandName, args));
    lastResult = result;
    return result.success;
  };

  for (const command of registry.getAll()) {
    api[command.name] = (...args: unknown[]) => {
      return invoke(command.name, args);
    };
  }

  api.pattern = {
    create: (...args: unknown[]) => invoke("pattern_create", args),
    offset: (...args: unknown[]) => invoke("pattern_offset", args),
  };
  api.seh = {
    visualize: (...args: unknown[]) => invoke("seh", args),
  };

  api.last_result = () => lastResult;
  api.last_summary = () => {
    if (!lastResult) {
      return {
        success: false,
        command: "",
        warnings: 0,
        errors: 0,
        findings: 0,
      };
    }
    return {
      success: lastResult.success,
      command: lastResult.command,
      warnings: lastResult.warnings.length,
      errors: lastResult.errors.length,
      findings: lastResult.findings.length,
    };
  };
  api.clear_last_result = () => {
    lastResult = undefined;
    return true;
  };

  api.sc = createShellcodeNamespace();

  return api;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseHexByteList(value: unknown): number[] | unknown {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value !== "string") {
    return value;
  }
  const tokens = value.split(/[,\s]+/).filter((token) => token.length > 0);
  if (tokens.length === 0) {
    return [];
  }
  const parsed: number[] = [];
  for (const token of tokens) {
    if (/^[0-9a-fA-F]{1,2}$/.test(token)) {
      parsed.push(parseInt(token, 16));
      continue;
    }

    if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
      for (let i = 0; i < token.length; i += 2) {
        parsed.push(parseInt(token.slice(i, i + 2), 16));
      }
      continue;
    }

    return value;
  }
  return parsed;
}

function normalizeInvocation(commandName: string, args: unknown[]): Record<string, unknown> {
  if (args.length === 0 || (args.length === 1 && args[0] === undefined)) {
    return {};
  }

  if (args.length === 1 && isPlainObject(args[0])) {
    return args[0];
  }

  switch (commandName) {
    case "help":
      return { command: args[0] };
    case "pattern_create":
      return { length: args[0], type: args[1] };
    case "pattern_offset":
      return { value: args[0], type: args[1] };
    case "badchars":
      return { address: args[0], exclude: parseHexByteList(args[1]) };
    case "egghunter":
      return { tag: args[0], mode: args[1], wow64: args[2] };
    case "exploit":
      return { mode: args[0], tag: args[1], offset: args[2], address: args[3] };
    case "modules":
      return { filter: args[0] };
    case "rop":
    case "rop_suggest":
    case "pivots":
    case "retn":
    case "add_esp":
      return {
        module: args[0],
        maxResults: args[1],
        executableOnly: args[2],
        mode: args[3],
      };
    case "nop":
      return { length: args[0], byte: args[1] };
    case "rop_template":
      return { api: args[0], module: args[1] };
    case "encode":
      return {
        shellcode: args[0],
        exclude: parseHexByteList(args[1]),
        key: args[2],
      };
    case "find_bytes":
      return {
        module: args[0],
        bytes: parseHexByteList(args[1]),
        maxResults: args[2],
        executableOnly: args[3],
        mode: args[4],
      };
    case "reload":
    case "seh":
      return {};
    case "seh_ppr":
      return {
        module: args[0],
        exclude: parseHexByteList(args[1]),
        maxResults: args[2],
        executableOnly: args[3],
        mode: args[4],
      };
    case "triage":
      return {
        patternLength: args[0],
        badchars: parseHexByteList(args[1]),
        module: args[2],
        stackBytes: args[3],
      };
    default:
      return { value: args[0] };
  }
}

function initialize(): void {
  registry.setReloader(() => {
    registerAll();
    osed = bindApi();
    publishOsed();
  });

  registerAll();
  osed = bindApi();
  publishOsed();
}

export function initializeScript(): unknown[] {
  const registrations: unknown[] = [];
  const hostAny = host as unknown as {
    apiVersionSupport?: new (major: number, minor: number) => unknown;
    functionAlias?: new (fn: (...args: unknown[]) => unknown, aliasName: string) => unknown;
  };

  if (hostAny.apiVersionSupport) {
    registrations.push(new hostAny.apiVersionSupport(1, 7));
  }

  initialize();

  if (hostAny.functionAlias) {
    registrations.push(new hostAny.functionAlias(() => osed, "osed"));
  }

  return registrations;
}
