import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { tool } from '@strands-agents/sdk';
import z from 'zod';
import { UvManager } from '../../../src/shared/scanner-tools/uv-manager.js';
import { ScannerToolManager } from '../../../src/shared/scanner-tools/scanner-tool-manager.js';
import { ScanTool } from '../../../src/shared/scanner-tools/types.js';
import { UnitTestRunner } from '../shared/unit-test-runner.js';
import { assessTestFile } from './test-discrimination.js';

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

    public static createTestDiscriminationTool(controlFilePath: string, srtRootPath: string) {
        return tool({
            name: 'check_tests_prove_requirement',
            description: 'Check whether a test file actually proves its requirement. Runs the file twice, once against a control replaced by one that reports a finding for every input, and once against a control that reports nothing. A file that keeps passing under either is satisfied by a control that hardcodes that answer, and so proves nothing. Call this for every test file you write, before you finish.',
            inputSchema: z.object({
                filePath: z.string().describe('The absolute path of the test file to assess'),
            }),
            callback: async ({ filePath }) => {
                const { outcome, reason } = await assessTestFile(filePath, controlFilePath, srtRootPath);
                return { acceptable: outcome === 'proves' || outcome === 'exempt', outcome, reason };
            },
        });
    }

    public static createFolderVitestTool(srtRootPath: string, testsFolderPath: string) {
        return tool({
            name: 'run_vitest',
            description: 'Run unit tests. Returns the test output including pass/fail status and error messages.',
            callback: async () => {
                const { passed, output } = new UnitTestRunner(srtRootPath, testsFolderPath).run();
                return { passed, output };
            },
        });
    }

    public static createTerraformValidateTool(terraformProjectPath: string) {
        return tool({
            name: 'run_terraform_validate',
            description: 'Run terraform init, validate, and plan against the Terraform fixture project to check for HCL, configuration, and planning errors. Plan runs with dummy credentials and no AWS access, so live data sources will fail here. Returns pass/fail and any error messages.',
            callback: async () => {
                const steps = [['init', '-backend=false', '-input=false'], ['validate', '-no-color'], ['plan', '-input=false', '-no-color']];
                let output = '';
                for (const args of steps) {
                    const result = spawnSync('terraform', args, { cwd: terraformProjectPath, encoding: 'utf8', timeout: 120_000 });
                    output += (result.stdout ?? '') + (result.stderr ?? '');
                    if (result.status !== 0) return { passed: false, output };
                }
                return { passed: true, output };
            },
        });
    }

    /** cfn-lint is installed and launched through uv rather than being on the PATH. */
    public static async runCfnLint(templatePath: string, extraArgs: string[] = [], timeoutMs = 60_000) {
        const uvPath = await UvManager.ensureUvAvailable();
        const toolArgs = ScannerToolManager.getToolRunArgs(ScanTool.CFN_LINT);

        return spawnSync(uvPath, [...toolArgs, ...extraArgs, templatePath], { encoding: 'utf8', timeout: timeoutMs });
    }

    public static createCfnLintTool(cfnProjectPath: string) {
        return tool({
            name: 'run_cfn_lint',
            description: 'Run cfn-lint against the CloudFormation fixture template (template.yaml) to check for syntax and schema errors. Returns pass/fail and any error messages.',
            callback: async () => {
                const result = await AgentToolFactory.runCfnLint(path.join(cfnProjectPath, 'template.yaml'));
                return { passed: result.status === 0, output: (result.stdout ?? '') + (result.stderr ?? '') };
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
