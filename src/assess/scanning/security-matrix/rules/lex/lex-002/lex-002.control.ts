import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Lex002Adapter } from './lex-002.adapter.js';

const OBFUSCATION_DISABLED = 'obfuscation-disabled';

const FINDINGS = {
  [OBFUSCATION_DISABLED]: {
    issue: (adapter: Lex002Adapter) => `Slot value obfuscation is not enabled for conversational bot slot(s): ${adapter.findSlotsWithoutObfuscation().join(', ')}, so captured values appear in plain text in conversation logs`,
    remediation: 'Ensure that EVERY slot defined in the conversational bot has slot value obfuscation explicitly enabled — not just the one slot flagged in the finding.\n\nApply the following to each slot inside each intent of each bot locale, without exception:\n1. The slot must include an explicit obfuscation configuration block. Omitting it (or leaving it null/empty) is treated as obfuscation disabled and will still fail.\n2. Inside that block, the obfuscation type value must be explicitly set to the default obfuscation type (the value `DefaultObfuscation`). It must not be absent, null, empty, or the value `None` (case-insensitive, including surrounding whitespace).\n\nDo not remove slots or intents to satisfy the rule; instead add/repair the obfuscation configuration on each existing slot. After the change, no slot anywhere in the bot definition may be missing an obfuscation type or use `None`.\n',
  },
} as const satisfies Record<string, Finding<Lex002Adapter>>;

type FindingKey = keyof typeof FINDINGS;

export class Lex002Control extends SecurityControl<Lex002Adapter, FindingKey> {
  constructor() {
    super({
      id: 'LEX-002',
      priority: 'HIGH',
      description: 'Amazon Lex V2 bot slots must have obfuscation enabled (not set to "None"/disabled) for slot values',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Lex002Adapter): FindingKey | null {
    const unobfuscatedSlots = adapter.findSlotsWithoutObfuscation();
    if (unobfuscatedSlots.length === 0) return null;
    return OBFUSCATION_DISABLED;
  }
}

export const lex002Control = new Lex002Control();
