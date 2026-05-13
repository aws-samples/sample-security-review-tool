import * as path from 'node:path';
import { SemgrepFixes } from '../../../../../src/assess/scanning/semgrep/semgrep-fixes.js';
import type { FixtureFormat, RuleEntry } from '../types/rule-catalog.js';
import { sha256OfFile } from './hash.js';

const SCANNER = 'semgrep' as const;

const LANGUAGE_PREFIX_MAP: Record<string, FixtureFormat> = {
    'python': 'python',
    'javascript': 'javascript',
    'typescript': 'javascript',
    'go': 'go',
    'java': 'java',
    'scala': 'java',
    'yaml': 'yaml',
};

export function loadSemgrepRules(srtRepoRoot: string): RuleEntry[] {
    const sourceFile = path.join(srtRepoRoot, 'src', 'assess', 'scanning', 'semgrep', 'semgrep-fixes.ts');
    const sourceHash = sha256OfFile(sourceFile);

    return Object.entries(SemgrepFixes).map(([checkId, fixGuidance]) => ({
        checkId,
        scanner: SCANNER,
        priority: 'MEDIUM' as const,
        description: deriveDescription(checkId, fixGuidance),
        fixGuidance,
        sourceLocation: sourceFile,
        sourceHash,
        applicableFormats: [inferFormat(checkId)],
    }));
}

function deriveDescription(checkId: string, fixGuidance: string): string {
    const firstSentence = fixGuidance.split(/\.\s/)[0];
    return `Semgrep ${checkId}: ${firstSentence}`;
}

function inferFormat(checkId: string): FixtureFormat {
    const prefix = checkId.split('.')[0].toLowerCase();
    return LANGUAGE_PREFIX_MAP[prefix] ?? 'python';
}
