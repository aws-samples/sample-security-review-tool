import { spawnSync } from 'node:child_process';

export interface UnitTestResult { passed: boolean; output: string; }

export class UnitTestRunner {
    constructor(private readonly srtRootFolderPath: string, private readonly testsFolderPath: string) { }

    public run(): UnitTestResult {
        const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', this.testsFolderPath], { cwd: this.srtRootFolderPath, encoding: 'utf8', timeout: 60_000 });
        const output = (result.stdout ?? '') + (result.stderr ?? '');
        return { passed: result.status === 0, output };
    }
}
