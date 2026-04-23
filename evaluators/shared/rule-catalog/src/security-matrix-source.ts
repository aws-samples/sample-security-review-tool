import * as fs from 'node:fs';
import * as path from 'node:path';
import { glob } from 'glob';
import { allRules } from '../../../../src/assess/scanning/security-matrix/rules/index.js';
import type { RuleEntry } from './types.js';
import { sha256OfFile, sha256OfString } from './hash.js';

const SCANNER = 'security-matrix' as const;

export async function loadSecurityMatrixRules(srtRepoRoot: string): Promise<RuleEntry[]> {
    const rulesDir = path.join(srtRepoRoot, 'src', 'assess', 'scanning', 'security-matrix', 'rules');
    const sourceIndex = await buildRuleIdToSourceIndex(rulesDir);

    return allRules.map(rule => {
        const sourceFile = sourceIndex.get(rule.id);
        const sourceLocation = sourceFile ?? path.join(rulesDir, `${rule.id}-unknown.ts`);
        const ruleBody = sourceFile ? fs.readFileSync(sourceFile, 'utf8') : '';
        const sourceHash = sourceFile ? sha256OfFile(sourceFile) : sha256OfString(rule.id);

        return {
            checkId: rule.id,
            scanner: SCANNER,
            service: inferServiceFromPath(sourceFile, rulesDir),
            priority: rule.priority,
            description: rule.description,
            fixGuidance: extractRepresentativeFixGuidance(ruleBody) || '(fix text emitted at scan time)',
            sourceLocation,
            sourceHash,
            applicableResourceTypes: rule.applicableResourceTypes.slice(),
            applicableFormats: ['cfn', 'cdk'],
            ruleBody,
        };
    });
}

async function buildRuleIdToSourceIndex(rulesDir: string): Promise<Map<string, string>> {
    const files = await glob('**/*.ts', { cwd: rulesDir, nodir: true, ignore: ['**/index.ts'] });
    const index = new Map<string, string>();
    for (const relative of files) {
        const absolute = path.join(rulesDir, relative);
        const contents = fs.readFileSync(absolute, 'utf8');
        const id = extractRuleIdFromSource(contents);
        if (id && !index.has(id)) {
            index.set(id, absolute);
        }
    }
    return index;
}

function extractRuleIdFromSource(source: string): string | null {
    // Match the first single- or double-quoted string literal passed to `super(`.
    // Rules consistently call `super('S3-008', 'HIGH', ...)` as the first statement.
    const match = source.match(/super\s*\(\s*['"]([A-Z][A-Z0-9_-]+)['"]/);
    return match ? match[1] : null;
}

function inferServiceFromPath(filePath: string | undefined, rulesDir: string): string | undefined {
    if (!filePath) return undefined;
    const relative = path.relative(rulesDir, filePath);
    const firstSegment = relative.split(path.sep)[0];
    return firstSegment && firstSegment !== relative ? firstSegment : undefined;
}

function extractRepresentativeFixGuidance(ruleBody: string): string {
    // Rules build fix text inline; pull the first string passed as the `fix` argument
    // to createResult/createScanResult for a best-effort representative snippet.
    const createCall = ruleBody.match(/create(?:Scan)?Result\s*\(([\s\S]*?)\)\s*;/);
    if (!createCall) return '';
    const args = createCall[1];
    // Fix text is typically the last string literal or joined array in the call.
    const arrayJoin = args.match(/\[\s*([\s\S]*?)\s*\]\s*\.join\(/);
    if (arrayJoin) {
        const lines = [...arrayJoin[1].matchAll(/`([^`]*)`|'([^']*)'|"([^"]*)"/g)]
            .map(m => m[1] ?? m[2] ?? m[3])
            .filter(Boolean);
        return lines.join('\n').trim();
    }
    const literals = [...args.matchAll(/`([^`]*)`|'([^']*)'|"([^"]*)"/g)]
        .map(m => m[1] ?? m[2] ?? m[3])
        .filter(Boolean);
    return literals.length > 0 ? literals[literals.length - 1].trim() : '';
}
