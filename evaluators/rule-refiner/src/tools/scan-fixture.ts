import * as fs from 'node:fs';
import * as path from 'node:path';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import { AssessCoordinator } from '../../../../src/assess/coordinator.js';
import type { ScanResult, RefinerSession } from '../types.js';

export function createScanFixtureTool(session: RefinerSession) {
    return tool({
        name: 'scan_fixture',
        description: 'Scan a fixture directory with AssessCoordinator. Returns whether the target rule fired, how many times, and any extra same-scanner findings.',
        inputSchema: z.object({
            fixtureDir: z.string().min(1).describe('Absolute path to the fixture directory.'),
            targetCheckId: z.string().min(1).describe('The check ID to look for (e.g. "S3-001").'),
            scanner: z.string().min(1).describe('Scanner name, e.g. "security-matrix".'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.fixtureDir);
            if (!resolved.startsWith(session.fixturesRoot)) {
                return { error: `fixtureDir must be under ${session.fixturesRoot}` };
            }

            const coordinator = new AssessCoordinator(resolved, () => {});
            try {
                await coordinator.assess('Apache-2.0', false, false, false, false);
            } catch (error) {
                return { error: `Scan failed: ${(error as Error).message}` };
            }

            const issues = readIssues(resolved);
            const activeIssues = issues.filter(i => i.status !== 'fixed' && i.status !== 'resolved');
            const targetFindings = activeIssues.filter(i => i.check_id === input.targetCheckId);
            const sameScannerOthers = activeIssues.filter(
                i => i.source === input.scanner && i.check_id !== input.targetCheckId,
            );

            session.preFixIssues.set(input.targetCheckId, activeIssues);

            return {
                targetRuleFired: targetFindings.length > 0,
                targetRuleFiredCount: targetFindings.length,
                otherSameScannerFindings: sameScannerOthers.map(i => i.check_id ?? 'unknown'),
                allFindings: activeIssues.map(i => ({
                    checkId: i.check_id ?? 'unknown',
                    source: i.source,
                    path: i.path ?? 'unknown',
                })),
            };
        },
    });
}

function readIssues(projectPath: string): ScanResult[] {
    const issuesPath = path.join(projectPath, '.srt', 'issues.json');
    if (!fs.existsSync(issuesPath)) return [];
    try {
        return JSON.parse(fs.readFileSync(issuesPath, 'utf8')) as ScanResult[];
    } catch {
        return [];
    }
}
