import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';

const RUN_TIMEOUT_MS = 120_000;

type Stub = 'always-flags' | 'never-flags';

export type DiscriminationOutcome = 'proves' | 'proves-nothing' | 'exempt' | 'broken';

export interface DiscriminationResult {
    outcome: DiscriminationOutcome;
    reason: string;
}

interface StubRun {
    ran: number;
    failed: number;
    skipped: number;
    crashed: boolean;
    detail: string;
}

/**
 * Answers whether a test file proves its requirement, by running it against a control stubbed to flag
 * every input and again against one stubbed to flag nothing. A file that survives either stub is
 * satisfied by a control that hardcodes that answer, so it cannot fail for the right reason.
 *
 * The real control is never used, so this is meaningful before the implementation exists — a red-phase
 * failure against the real control says nothing about whether the file discriminates.
 */
export async function assessTestFile(testFilePath: string, controlFilePath: string, srtRootPath: string): Promise<DiscriminationResult> {
    if (!fs.existsSync(testFilePath)) return { outcome: 'broken', reason: 'the file was not created' };

    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'srt-discrimination-'));
    try {
        const [alwaysFlags, neverFlags] = await Promise.all([
            runAgainstStub('always-flags', workspace, testFilePath, controlFilePath, srtRootPath),
            runAgainstStub('never-flags', workspace, testFilePath, controlFilePath, srtRootPath),
        ]);
        return interpret(alwaysFlags, neverFlags);
    } finally {
        fs.rmSync(workspace, { recursive: true, force: true });
    }
}

function interpret(alwaysFlags: StubRun, neverFlags: StubRun): DiscriminationResult {
    if (alwaysFlags.crashed || neverFlags.crashed) {
        return { outcome: 'broken', reason: `the file did not run: ${alwaysFlags.detail || neverFlags.detail}` };
    }
    if (alwaysFlags.ran === 0) {
        return { outcome: 'exempt', reason: 'every test in the file is skipped, so there is nothing to prove' };
    }
    if (alwaysFlags.failed === 0) {
        return { outcome: 'proves-nothing', reason: 'every test still passes when the control is replaced by one that flags every input, so a control that reports a finding for everything satisfies this file' };
    }
    if (neverFlags.failed === 0) {
        return { outcome: 'proves-nothing', reason: 'every test still passes when the control is replaced by one that never flags, so a control that reports nothing satisfies this file' };
    }
    return { outcome: 'proves', reason: 'the file fails against a control that flags everything and against one that flags nothing, so it distinguishes the two' };
}

function runAgainstStub(stub: Stub, workspace: string, testFilePath: string, controlFilePath: string, srtRootPath: string): Promise<StubRun> {
    const configPath = writeHarness(stub, workspace, controlFilePath);
    const reportPath = path.join(workspace, `report-${stub}.json`);

    return new Promise(resolve => {
        const child = spawn('npx', ['vitest', 'run', '--config', configPath, '--reporter=json', `--outputFile=${reportPath}`, testFilePath], {
            cwd: srtRootPath,
            timeout: RUN_TIMEOUT_MS,
            killSignal: 'SIGKILL',
        });

        let stderr = '';
        child.stderr.on('data', chunk => { stderr += chunk; });
        child.stdout.on('data', () => {});
        child.on('close', code => resolve(readReport(reportPath, code, stderr)));
        child.on('error', error => resolve({ ran: 0, failed: 0, skipped: 0, crashed: true, detail: error.message }));
    });
}

// A plain object rather than defineConfig: the config lives outside the project, where 'vitest/config'
// does not resolve. The stub patches the control class prototype, because generated tests reach the
// control both through the exported singleton and by constructing the class themselves.
function writeHarness(stub: Stub, workspace: string, controlFilePath: string): string {
    const verdict = stub === 'always-flags'
        ? `{ scenario: this.remediationScenarios?.[0]?.scenario ?? 'probe', issue: 'discrimination probe' }`
        : 'null';

    const setupPath = path.join(workspace, `stub-${stub}.ts`);
    fs.writeFileSync(setupPath, [
        `import * as controlModule from ${JSON.stringify(controlFilePath)};`,
        `let patched = 0;`,
        `for (const exported of Object.values(controlModule)) {`,
        `    if (exported === null || exported === undefined) continue;`,
        `    const prototype = typeof exported === 'function' ? exported.prototype : Object.getPrototypeOf(exported);`,
        `    if (prototype && typeof prototype.evaluate === 'function') {`,
        `        prototype.evaluate = function () { return ${verdict}; };`,
        `        patched++;`,
        `    }`,
        `}`,
        `if (patched === 0) throw new Error('The discrimination probe found no control to stub.');`,
        '',
    ].join('\n'));

    const configPath = path.join(workspace, `vitest-${stub}.config.ts`);
    fs.writeFileSync(configPath, `export default { test: { setupFiles: [${JSON.stringify(setupPath)}] } };\n`);
    return configPath;
}

function readReport(reportPath: string, exitCode: number | null, stderr: string): StubRun {
    if (!fs.existsSync(reportPath)) {
        return { ran: 0, failed: 0, skipped: 0, crashed: true, detail: firstLine(stderr) || `vitest exited ${exitCode} without writing a report` };
    }

    try {
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        const total = report.numTotalTests ?? 0;
        const skipped = report.numPendingTests ?? 0;
        const suiteErrors = (report.testResults ?? []).filter((suite: { status?: string; assertionResults?: unknown[] }) =>
            suite.status === 'failed' && (suite.assertionResults ?? []).length === 0);

        return {
            ran: total - skipped,
            failed: report.numFailedTests ?? 0,
            skipped,
            crashed: total === 0 && suiteErrors.length > 0,
            detail: firstLine(suiteErrors[0]?.message ?? '') || firstLine(stderr),
        };
    } catch (error) {
        return { ran: 0, failed: 0, skipped: 0, crashed: true, detail: `unreadable vitest report: ${(error as Error).message}` };
    }
}

function firstLine(text: string): string {
    return text.split('\n').map(line => line.trim()).find(line => line.length > 0) ?? '';
}
