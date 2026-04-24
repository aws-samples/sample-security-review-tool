import { spawn } from 'node:child_process';
import * as readline from 'node:readline';

export class ClaudeRunner {
    private readonly cwd: string;

    constructor(cwd: string) {
        this.cwd = cwd;
    }

    public run(prompt: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const child = spawn(
                'claude',
                ['-p', '--permission-mode', 'acceptEdits', '--output-format', 'stream-json', '--verbose'],
                { cwd: this.cwd, stdio: ['pipe', 'pipe', 'inherit'] },
            );

            const rl = readline.createInterface({ input: child.stdout! });
            rl.on('line', line => this.extractAndPrint(line));

            child.stdin!.end(prompt);
            child.on('error', reject);
            child.on('close', code => {
                if (code !== 0) reject(new Error(`Claude CLI exited with code ${code}`));
                else resolve();
            });
        });
    }

    private extractAndPrint(line: string): void {
        if (!line.trim()) return;
        try {
            const parsed = JSON.parse(line);
            const contents = parsed?.message?.content;
            if (!Array.isArray(contents)) return;
            for (const block of contents) {
                if (block.type === 'text' && block.text) {
                    process.stdout.write(block.text + '\n');
                }
            }
        } catch {
            // Non-JSON line from verbose output
        }
    }
}
