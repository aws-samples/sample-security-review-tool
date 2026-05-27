import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { tool } from '@strands-agents/sdk';
import z from 'zod';

export class AgentToolFactory {
    public static createWriteFileTool(options: { ensureDir: boolean } = { ensureDir: false }) {
        return tool({
            name: 'write_file',
            description: 'Write the complete file content.',
            inputSchema: z.object({
                filePath: z.string().describe('The absolute path of the file to write'),
                content: z.string().describe('The complete file content'),
            }),
            callback: async ({ filePath, content }) => {
                if (options.ensureDir) {
                    fs.mkdirSync(path.dirname(filePath), { recursive: true });
                }
                fs.writeFileSync(filePath, content);
                return 'Written successfully.';
            },
        });
    }

    public static createReadUnitTestTool(testsFolderPath: string) {
        return tool({
            name: 'read_unit_tests',
            description: 'Read the contents of a unit test file within the tests folder.',
            inputSchema: z.object({
                filePath: z.string().describe('The absolute path of the test file to read'),
            }),
            callback: async ({ filePath }) => {
                const resolved = path.resolve(filePath);
                if (!resolved.startsWith(testsFolderPath)) {
                    return `Error: path must be within ${testsFolderPath}`;
                }
                if (!fs.existsSync(resolved)) {
                    return `Error: file not found: ${resolved}`;
                }
                return fs.readFileSync(resolved, 'utf8');
            },
        });
    }

    public static createSingleFileVitestTool(srtRootPath: string) {
        return tool({
            name: 'run_vitest',
            description: 'Run Vitest against the test file to check if tests pass or fail. Returns the test output including pass/fail status and error messages.',
            inputSchema: z.object({
                filePath: z.string().describe('The absolute path of the test file to run with Vitest'),
            }),
            callback: async ({ filePath }) => {
                const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', filePath], { cwd: srtRootPath, encoding: 'utf8', timeout: 60_000 });
                const output = ((result.stdout ?? '') + (result.stderr ?? ''));
                return { passed: result.status === 0, output };
            },
        });
    }

    public static createFolderVitestTool(srtRootPath: string, testsFolderPath: string) {
        return tool({
            name: 'run_vitest',
            description: 'Run unit tests. Returns the test output including pass/fail status and error messages.',
            callback: async () => {
                const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', testsFolderPath], { cwd: srtRootPath, encoding: 'utf8', timeout: 60_000 });
                const output = ((result.stdout ?? '') + (result.stderr ?? ''));
                return { passed: result.status === 0, output };
            },
        });
    }

    public static createTscTool(cdkProjectPath: string) {
        return tool({
            name: 'run_tsc',
            description: 'Run the TypeScript compiler against the CDK fixture project to check for compilation errors. Returns pass/fail and any error messages.',
            callback: async () => {
                const result = spawnSync('npx', ['tsc', '--noEmit'], { cwd: cdkProjectPath, encoding: 'utf8', timeout: 30_000 });
                const output = ((result.stdout ?? '') + (result.stderr ?? ''));
                return { passed: result.status === 0, output };
            },
        });
    }
}
