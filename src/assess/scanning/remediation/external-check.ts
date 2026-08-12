import { BanditFixes } from '../bandit/bandit-fixes.js';
import { CheckovPolicies } from '../checkov/checkov_fixes.js';
import { SemgrepFixes } from '../semgrep/semgrep-fixes.js';
import type { Remediation } from './types.js';

type Registry = Record<string, Omit<Remediation, 'id'>>;

const REGISTRIES: Registry[] = [CheckovPolicies, BanditFixes, SemgrepFixes];

export function externalCheck(checkId: string): Remediation {
    const row = REGISTRIES.map(registry => registry[checkId]).find(Boolean);
    return { id: checkId, priority: row?.priority ?? 'INFO', description: row?.description, intent: row?.intent ?? '' };
}
