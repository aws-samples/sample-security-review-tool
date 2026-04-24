import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import { FixCoordinator } from '../../../../src/fix/coordinator.js';
import { SrtLogger } from '../../../../src/shared/logging/srt-logger.js';
import type { ScanResult, RefinerSession, FixSessionSummary } from '../types.js';

const LOG_FILE_NAME = 'srt-tool.log';

export function createRunFixTool(session: RefinerSession) {
    return tool({
        name: 'run_fix',
        description: 'Run the SRT fix agent against a single finding in a fixture. Returns the git diff and a session summary (turns, retries, failures).',
        inputSchema: z.object({
            fixtureDir: z.string().min(1).describe('Absolute path to the fixture directory (must have been scanned first).'),
            checkId: z.string().min(1).describe('The check ID of the finding to fix.'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.fixtureDir);
            if (!resolved.startsWith(session.fixturesRoot)) {
                return { error: `fixtureDir must be under ${session.fixturesRoot}` };
            }

            const issue = findIssue(resolved, input.checkId);
            if (!issue) {
                return { error: `No finding with check_id=${input.checkId} in ${resolved}/.srt/issues.json` };
            }

            const logsFolderPath = path.join(os.homedir(), '.srt', 'logs');
            const logOffset = currentLogSize(logsFolderPath);

            let coordinator: FixCoordinator;
            try {
                coordinator = await FixCoordinator.create(resolved, () => {});
            } catch (error) {
                return { error: `FixCoordinator.create failed: ${(error as Error).message}` };
            }

            let applied = false;
            try {
                const fix = await coordinator.generateFix(issue);
                if (fix) {
                    await coordinator.applyFix(issue, fix);
                    applied = true;
                }
            } catch (error) {
                SrtLogger.logError('run_fix: fix generation/application failed', error as Error, {
                    checkId: input.checkId,
                });
            }

            const diff = applied ? gitDiff(resolved) : '';
            const sessionSummary = parseSessionSummary(logsFolderPath, logOffset, issue);
            gitStageAll(resolved);

            return {
                success: applied,
                diff: diff.slice(0, 30000),
                turns: sessionSummary.turns,
                applyFixAttempts: sessionSummary.applyFixAttempts,
                applyFixFailures: sessionSummary.applyFixFailures,
                stopReason: sessionSummary.stopReason,
                finalComments: sessionSummary.finalComments,
            };
        },
    });
}

function findIssue(projectPath: string, checkId: string): ScanResult | null {
    const issuesPath = path.join(projectPath, '.srt', 'issues.json');
    if (!fs.existsSync(issuesPath)) return null;
    try {
        const issues = JSON.parse(fs.readFileSync(issuesPath, 'utf8')) as ScanResult[];
        return issues.find(i => i.check_id === checkId) ?? null;
    } catch {
        return null;
    }
}

function currentLogSize(logsFolderPath: string): number {
    const logFile = findTodaysLog(logsFolderPath);
    if (!logFile || !fs.existsSync(logFile)) return 0;
    return fs.statSync(logFile).size;
}

function findTodaysLog(logsFolderPath: string): string | null {
    if (!fs.existsSync(logsFolderPath)) return null;
    const files = fs.readdirSync(logsFolderPath)
        .filter(name => name.startsWith(`${LOG_FILE_NAME}.`))
        .sort();
    if (files.length === 0) return null;
    return path.join(logsFolderPath, files[files.length - 1]);
}

function parseSessionSummary(
    logsFolderPath: string,
    byteOffset: number,
    issue: ScanResult,
): FixSessionSummary {
    const logFile = findTodaysLog(logsFolderPath);
    if (!logFile || !fs.existsSync(logFile)) {
        return { turns: 0, applyFixAttempts: 0, applyFixFailures: 0, stopReason: 'no-log', finalComments: '' };
    }

    const size = fs.statSync(logFile).size;
    if (size <= byteOffset) {
        return { turns: 0, applyFixAttempts: 0, applyFixFailures: 0, stopReason: 'no-new-log', finalComments: '' };
    }

    const buffer = Buffer.alloc(size - byteOffset);
    const fd = fs.openSync(logFile, 'r');
    try {
        fs.readSync(fd, buffer, 0, buffer.length, byteOffset);
    } finally {
        fs.closeSync(fd);
    }

    const lines = buffer.toString('utf8').split('\n').filter(l => l.length > 0);
    return extractSummaryFromLines(lines, issue);
}

function extractSummaryFromLines(lines: string[], issue: ScanResult): FixSessionSummary {
    const SESSION_STARTED = 'StrandsFixAgent: session started';
    const SESSION_ENDED = 'StrandsFixAgent: session ended';
    const TOOL_RESULT = 'StrandsFixAgent: tool result';

    const startIdx = lines.findIndex(l =>
        l.includes(SESSION_STARTED) && (!issue.check_id || l.includes(issue.check_id)),
    );
    if (startIdx === -1) {
        return { turns: 0, applyFixAttempts: 0, applyFixFailures: 0, stopReason: 'session-not-found', finalComments: '' };
    }

    let endIdx = lines.length;
    for (let i = startIdx + 1; i < lines.length; i++) {
        if (lines[i].includes(SESSION_ENDED)) { endIdx = i + 1; break; }
    }

    const block = lines.slice(startIdx, endIdx);
    const toolLines = block.filter(l => l.includes(TOOL_RESULT));
    const applyFixLines = toolLines.filter(l => l.includes('tool=apply_fix'));
    const failedLines = applyFixLines.filter(l => l.includes('isFailure=true') || l.includes('isError=true'));

    const endedLine = block.findLast(l => l.includes(SESSION_ENDED));
    const endedFields = endedLine ? parseSimpleFields(endedLine) : {};

    return {
        turns: Number(endedFields.turns) || toolLines.length,
        applyFixAttempts: applyFixLines.length,
        applyFixFailures: failedLines.length,
        stopReason: stripQuotes(endedFields.stopReason ?? 'unknown'),
        finalComments: stripQuotes(endedFields.comments ?? ''),
    };
}

function parseSimpleFields(line: string): Record<string, string> {
    const result: Record<string, string> = {};
    const open = line.indexOf('{');
    if (open === -1) return result;
    const payload = line.slice(open + 1, line.lastIndexOf('}'));
    for (const part of payload.split(', ')) {
        const eq = part.indexOf('=');
        if (eq > 0) result[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
    }
    return result;
}

function stripQuotes(value: string): string {
    if (value.startsWith('"') && value.endsWith('"')) return value.slice(1, -1);
    return value;
}

function gitDiff(cwd: string): string {
    const result = spawnSync('git', ['diff'], { cwd, encoding: 'utf8' });
    return result.status === 0 ? result.stdout : '';
}

function gitStageAll(cwd: string): void {
    spawnSync('git', ['add', '-A'], { cwd, encoding: 'utf8' });
}
