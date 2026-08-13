import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Lex002Adapter } from './lex-002.adapter.js';

const OBFUSCATION_DISABLED = 'obfuscation-disabled';

export class Lex002Control extends SecurityControl<Lex002Adapter> {
  constructor() {
    super({
      id: 'LEX-002',
      priority: 'HIGH',
      description: 'Amazon Lex V2 bot slots must have obfuscation enabled (not set to "None"/disabled) for slot values',
      remediationScenarios: [
        {
          scenario: OBFUSCATION_DISABLED,
          intent: 'Ensure that EVERY slot defined in the conversational bot has slot value obfuscation explicitly enabled — not just the one slot flagged in the finding.\n\nApply the following to each slot inside each intent of each bot locale, without exception:\n1. The slot must include an explicit obfuscation configuration block. Omitting it (or leaving it null/empty) is treated as obfuscation disabled and will still fail.\n2. Inside that block, the obfuscation type value must be explicitly set to the default obfuscation type (the value `DefaultObfuscation`). It must not be absent, null, empty, or the value `None` (case-insensitive, including surrounding whitespace).\n\nDo not remove slots or intents to satisfy the rule; instead add/repair the obfuscation configuration on each existing slot. After the change, no slot anywhere in the bot definition may be missing an obfuscation type or use `None`.\n',
        },
      ],
    });
  }

  protected evaluate(adapter: Lex002Adapter): ControlFinding | null {
    const unobfuscatedSlots = adapter.findSlotsWithoutObfuscation();
    if (unobfuscatedSlots.length === 0) return null;
    return {
      scenario: OBFUSCATION_DISABLED,
      issue: `Slot value obfuscation is not enabled for conversational bot slot(s): ${unobfuscatedSlots.join(', ')}, so captured values appear in plain text in conversation logs`,
    };
  }
}

export const lex002Control = new Lex002Control();
