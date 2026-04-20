import { spawnSync } from 'node:child_process';

/**
 * Thin wrapper around `git` for capturing per-finding diffs.
 *
 * After each finding is fixed we:
 *   - take the diff of the working tree (shows what the fix agent changed),
 *   - then stage those changes so the next finding's diff starts from a clean
 *     working tree.
 *
 * We intentionally do NOT commit — the evaluator leaves the user's git state
 * as staged changes, so they can review/commit/revert themselves.
 */
export class GitSnapshot {
    constructor(private readonly cwd: string) {}

    public async ensureGitRepository(): Promise<void> {
        const result = this.run(['rev-parse', '--is-inside-work-tree']);
        if (result.status !== 0) {
            throw new Error(`Not a git repository: ${this.cwd}. Evaluator requires git to capture per-finding diffs.`);
        }
    }

    public async diffUnstaged(): Promise<string> {
        const result = this.run(['diff']);
        return result.status === 0 ? result.stdout : '';
    }

    public async stageAll(): Promise<void> {
        this.run(['add', '-A']);
    }

    private run(args: string[]): { status: number; stdout: string; stderr: string } {
        const result = spawnSync('git', args, { cwd: this.cwd, encoding: 'utf8' });
        return {
            status: result.status ?? -1,
            stdout: result.stdout ?? '',
            stderr: result.stderr ?? '',
        };
    }
}
