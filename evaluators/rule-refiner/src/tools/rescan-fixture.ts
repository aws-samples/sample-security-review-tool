import * as fs from 'node:fs';
import * as path from 'node:path';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import { AssessCoordinator } from '../../../../src/assess/coordinator.js';
import type { ScanResult, RefinerSession } from '../types.js';

export function createRescanFixtureTool(session: RefinerSession) {
    return tool({
        name: 'rescan_fixture',
        description: 'Re-run assessment on a fixture after a fix has been applied. Compares pre-fix vs post-fix issues to determine if the target rule cleared and whether new rules were triggered.',
        inputSchema: z.object({
            fixtureDir: z.string().min(1).describe('Absolute path to the fixture directory.'),
            checkId: z.string().min(1).describe('The target check ID.'),
            scanner: z.string().min(1).describe('Scanner name, e.g. "security-matrix".'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.fixtureDir);
            if (!resolved.startsWith(session.fixturesRoot)) {
                return { error: `fixtureDir must be under ${session.fixturesRoot}` };
            }

            const coordinator = new AssessCoordinator(resolved, () => {});
            let validationPassed = true;
            let validationError: string | undefined;
            try {
                await coordinator.assess('Apache-2.0', false, false, false, false);
            } catch (error) {
                validationPassed = false;
                validationError = (error as Error).message;
            }

            const postFixIssues = readActiveIssues(resolved);
            const preFixIssues = session.preFixIssues.get(input.checkId) ?? [];

            const targetRuleStillFires = postFixIssues.some(i => i.check_id === input.checkId);
            const preFixCheckIds = new Set(preFixIssues.map(i => i.check_id).filter(Boolean));
            const newRulesTriggered = postFixIssues
                .filter(i => i.source === input.scanner && !preFixCheckIds.has(i.check_id))
                .map(i => i.check_id ?? 'unknown');

            return {
                targetRuleStillFires,
                newRulesTriggered: [...new Set(newRulesTriggered)],
                validationPassed,
                ...(validationError ? { validationError: validationError.slice(0, 500) } : {}),
            };
        },
    });
}

function readActiveIssues(projectPath: string): ScanResult[] {
    const issuesPath = path.join(projectPath, '.srt', 'issues.json');
    if (!fs.existsSync(issuesPath)) return [];
    try {
        const all = JSON.parse(fs.readFileSync(issuesPath, 'utf8')) as ScanResult[];
        return all.filter(i => i.status !== 'fixed' && i.status !== 'resolved');
    } catch {
        return [];
    }
}
