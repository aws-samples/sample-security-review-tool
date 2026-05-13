import * as path from 'node:path';
import { BanditFixes } from '../../../../../src/assess/scanning/bandit/bandit-fixes.js';
import type { RuleEntry } from '../types/rule-catalog.js';
import { sha256OfFile } from './hash.js';

const SCANNER = 'bandit' as const;

// BanditScanner overrides these two to HIGH regardless of Bandit's own severity.
const HIGH_PRIORITY_OVERRIDES = new Set(['B105', 'B106']);

export function loadBanditRules(srtRepoRoot: string): RuleEntry[] {
    const sourceFile = path.join(srtRepoRoot, 'src', 'assess', 'scanning', 'bandit', 'bandit-fixes.ts');
    const sourceHash = sha256OfFile(sourceFile);

    return Object.entries(BanditFixes).map(([checkId, fixGuidance]) => ({
        checkId,
        scanner: SCANNER,
        priority: HIGH_PRIORITY_OVERRIDES.has(checkId) ? 'HIGH' as const : 'MEDIUM' as const,
        description: deriveDescription(checkId, fixGuidance),
        fixGuidance,
        sourceLocation: sourceFile,
        sourceHash,
        applicableFormats: ['python'],
    }));
}

function deriveDescription(checkId: string, fixGuidance: string): string {
    // Bandit check IDs are opaque; first sentence of the fix is the best available description.
    const firstSentence = fixGuidance.split(/\.\s/)[0];
    return `Bandit ${checkId}: ${firstSentence}`;
}
