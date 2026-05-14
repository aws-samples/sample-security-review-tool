import { spawnSync } from 'node:child_process';
import { srtRepoRoot } from '../../shared/fixture-paths.js';

export function typecheckGeneratedTest(testPath: string): string[] {
    const result = spawnSync('npx', ['tsc', '--noEmit', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--target', 'ES2023', '--strict', '--esModuleInterop', '--skipLibCheck', testPath], { cwd: srtRepoRoot(), encoding: 'utf8', timeout: 30_000 });

    const output = (result.stdout ?? '') + (result.stderr ?? '');
    if (result.status === 0) return [];

    return output.split('\n').filter(line => line.includes(testPath));
}
