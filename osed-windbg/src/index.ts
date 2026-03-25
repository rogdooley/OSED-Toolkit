import { Command, CommandRegistry } from "./core/registry";
import { createPatternCommands } from "./commands/pattern";
import { createBadcharsCommand } from "./commands/badchars";
import { createEgghunterCommand } from "./commands/egghunter";
import { createSehCommand } from "./commands/seh";
import { createModulesCommand } from "./commands/modules";
import { createRopCommands } from "./commands/rop";
import { createPivotCommand } from "./commands/pivot";
import { createHelpCommand } from "./commands/help";
import { createReloadCommand } from "./commands/reload";

type OsedApi = {
  [name: string]: (options?: Record<string, unknown>) => unknown;
};

const registry = new CommandRegistry();
let osed: OsedApi = {};

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
    createHelpCommand(registry),
    createReloadCommand(registry),
  ];

  for (const command of commands) {
    registry.register(command);
  }
}

function bindApi(): OsedApi {
  const api: OsedApi = {};

  for (const command of registry.getAll()) {
    api[command.name] = (options?: Record<string, unknown>) => registry.execute(command.name, options ?? {});
  }

  return api;
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
  };

  if (hostAny.apiVersionSupport) {
    registrations.push(new hostAny.apiVersionSupport(1, 7));
  }

  initialize();
  return registrations;
}
