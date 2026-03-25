import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readPointer } from "../core/memory";
import { findModuleByAddress } from "./modules";

function toAddress(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }

  if (typeof value === "number") {
    return BigInt(Math.max(0, Math.trunc(value)));
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

  return BigInt(0);
}

function resolveTebAddress(): bigint {
  const thread = host.currentThread as Record<string, unknown>;

  const directCandidates: unknown[] = [
    thread.Teb,
    thread.Teb32,
    thread.TebAddress,
    thread.Wow64Teb,
    thread.Wow64Teb32,
  ];

  for (const candidate of directCandidates) {
    const parsed = toAddress(candidate);
    if (parsed !== BigInt(0)) {
      return parsed;
    }
  }

  for (const key of Object.keys(thread)) {
    if (!/teb/i.test(key)) {
      continue;
    }
    const parsed = toAddress(thread[key]);
    if (parsed !== BigInt(0)) {
      return parsed;
    }
  }

  return BigInt(0);
}

export function createSehCommand(): Command {
  return {
    name: "seh",
    description: "Walk current thread SEH chain.",
    usage: "dx @$osed.seh({})",
    examples: ["dx @$osed.seh({})", "dx @$osed.seh({})"],
    schema: {},
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      if (pointerSize !== 4) {
        return {
          command: "seh",
          args: options,
          success: false,
          findings: [],
          warnings: ["SEH chain walking is x86-focused in v1."],
          errors: ["Current pointer size is not x86."],
        };
      }

      const teb = resolveTebAddress();
      if (teb === BigInt(0)) {
        throw new Error("Current thread TEB is unavailable.");
      }

      const rows: Array<Record<string, string>> = [];
      const findings: unknown[] = [];

      let node = readPointer(teb, 4);
      let guard = 0;

      while (node !== BigInt(0xffffffff) && guard < 64) {
        const next = readPointer(node, 4);
        const handler = readPointer(node + BigInt(4), 4);
        const module = findModuleByAddress(handler);

        const safeSehRisk = module && module.safeseh !== "enabled" ? "risk" : "ok";
        const outsideModule = module === undefined;

        rows.push({
          node: out.formatAddress(node, 4),
          handler: out.formatAddress(handler, 4),
          target: module ? `${module.name}+0x${(handler - module.base).toString(16).toUpperCase()}` : "<outside module>",
          safeseh: module ? module.safeseh : "unknown",
          status: outsideModule || safeSehRisk === "risk" ? "flag" : "ok",
        });

        findings.push({
          node,
          next,
          handler,
          module: module?.name,
          outsideModule,
          safeSeh: module?.safeseh ?? "unknown",
        });

        node = next;
        guard += 1;
      }

      out.section("SEH Chain");
      out.table(
        [
          { key: "node", header: "Node", width: 10 },
          { key: "handler", header: "Handler", width: 10 },
          { key: "target", header: "Module+Offset", width: 24 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "status", header: "Status", width: 6 },
        ],
        rows,
      );
      out.whyItMatters("SEH handler control is a classic exploit path when stack overwrite is constrained.");

      return {
        command: "seh",
        args: options,
        success: true,
        findings,
        warnings: guard >= 64 ? ["SEH walk stopped at guard limit (64 entries)."] : [],
        errors: [],
      };
    },
  };
}
