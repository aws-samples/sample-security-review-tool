import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ContextLoader } from '../../../src/fix/agent/prompts/context-loader.js';
import { getSystemPrompt } from '../../../src/fix/agent/prompts/system-prompt.js';
import { EditSession } from '../../../src/fix/agent/staging/edit-session.js';
import { WorkspaceGuard } from '../../../src/fix/agent/staging/workspace-guard.js';
import { FixValidator } from '../../../src/fix/agent/validation/fix-validator.js';
import { TerraformValidateStrategy } from '../../../src/fix/agent/validation/strategies/terraform-validate-strategy.js';
import { ProjectContext } from '../../../src/shared/project/project-context.js';
import { ScanResult } from '../../../src/assess/scanning/types.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';

function createTerraformContext(workingDir: string, projectName: string): ProjectContext {
    return {
        getProjectRootFolderPath: () => workingDir,
        getTerraformPlans: async () => [{
            name: projectName,
            rootPath: path.join(workingDir, projectName),
            outputFolderPath: '',
        }],
        isCdkProject: async () => false,
        isCloudFormationTemplate: async () => false,
        getAllCdkProjects: async () => [],
        getFolderIgnorePatterns: () => ['**/node_modules/**', '**/.terraform/**'],
    } as unknown as ProjectContext;
}

function s3Issue(projectName: string): ScanResult {
    return {
        source: 'terraform-matrix',
        path: projectName,
        resourceType: 'aws_s3_bucket',
        resourceName: 'aws_s3_bucket.data',
        issue: 'S3 bucket does not have access logging enabled',
        fix: 'Add a logging block to the aws_s3_bucket resource or create an aws_s3_bucket_logging resource.',
        priority: 'HIGH',
        check_id: 'S3-001',
        status: 'Open',
    } as ScanResult;
}

describe('Terraform fix integration', () => {
    let workingDir: string;
    let tfDir: string;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tf-fix-integ-'));
        tfDir = path.join(workingDir, 'terraform');
        await fs.mkdir(tfDir, { recursive: true });
        SrtLogger.initialize(path.join(workingDir, 'logs'));
    });

    afterEach(async () => {
        vi.restoreAllMocks();
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    describe('context loading', () => {
        it('resolves the correct .tf file and line number for a terraform-matrix issue', async () => {
            await fs.writeFile(path.join(tfDir, 'main.tf'), [
                'resource "aws_vpc" "main" {',
                '  cidr_block = "10.0.0.0/16"',
                '}',
                '',
                'resource "aws_s3_bucket" "data" {',
                '  bucket = "my-data-bucket"',
                '}',
            ].join('\n'));

            const context = createTerraformContext(workingDir, 'terraform');
            const loader = new ContextLoader(context);
            const loaded = await loader.load(s3Issue('terraform'));

            expect(loaded.sources).toHaveLength(1);
            expect(loaded.sources[0].path).toBe(path.join(tfDir, 'main.tf'));
            expect(loaded.sources[0].focusLine).toBe(5);
            expect(loaded.sources[0].content).toContain('aws_s3_bucket');
        });

        it('returns empty sources when project is not found', async () => {
            const context = createTerraformContext(workingDir, 'other-project');
            const loader = new ContextLoader(context);
            const loaded = await loader.load(s3Issue('terraform'));

            expect(loaded.sources).toHaveLength(0);
        });

        it('resolves resource in a nested subdirectory', async () => {
            const modulesDir = path.join(tfDir, 'modules', 'storage');
            await fs.mkdir(modulesDir, { recursive: true });
            await fs.writeFile(path.join(modulesDir, 'bucket.tf'), [
                'resource "aws_s3_bucket" "data" {',
                '  bucket = var.bucket_name',
                '}',
            ].join('\n'));

            const context = createTerraformContext(workingDir, 'terraform');
            const loader = new ContextLoader(context);
            const loaded = await loader.load(s3Issue('terraform'));

            expect(loaded.sources).toHaveLength(1);
            expect(loaded.sources[0].path).toBe(path.join(modulesDir, 'bucket.tf'));
            expect(loaded.sources[0].focusLine).toBe(1);
        });
    });

    describe('system prompt selection', () => {
        it('returns HCL-specific guidance for terraform-matrix issues', () => {
            const prompt = getSystemPrompt('terraform-matrix');
            expect(prompt).toContain('HCL');
            expect(prompt).toContain('curly braces');
            expect(prompt).toContain('terraform fmt');
            expect(prompt).not.toContain('match the file\'s existing indentation exactly');
        });

        it('returns YAML guidance for non-terraform issues', () => {
            const prompt = getSystemPrompt('security-matrix');
            expect(prompt).toContain('YAML');
            expect(prompt).not.toContain('HCL');
        });

        it('returns YAML guidance when source is undefined', () => {
            const prompt = getSystemPrompt(undefined);
            expect(prompt).toContain('YAML');
        });
    });

    describe('validation with terraform fmt', () => {
        it('accepts a correctly-formatted fix to a .tf file', async () => {
            const filePath = path.join(tfDir, 'main.tf');
            const original = [
                'resource "aws_s3_bucket" "data" {',
                '  bucket = "my-data-bucket"',
                '}',
                '',
            ].join('\n');
            const fixed = [
                'resource "aws_s3_bucket" "data" {',
                '  bucket = "my-data-bucket"',
                '}',
                '',
                'resource "aws_s3_bucket_logging" "data" {',
                '  bucket        = aws_s3_bucket.data.id',
                '  target_bucket = aws_s3_bucket.data.id',
                '  target_prefix = "log/"',
                '}',
                '',
            ].join('\n');
            await fs.writeFile(filePath, original);

            const context = createTerraformContext(workingDir, 'terraform');
            const guard = new WorkspaceGuard(workingDir);
            const session = new EditSession(guard);

            const applied = await session.applyEdits([{
                path: 'terraform/main.tf',
                lineRange: [1, 4],
                newContent: fixed,
            }]);
            expect(applied.ok).toBe(true);

            const validator = new FixValidator(context, session.recorder, [
                new TerraformValidateStrategy(),
            ]);
            const result = await validator.validate();

            expect(result.isValid).toBe(true);
        });

        it('rejects a badly-formatted fix to a .tf file', async () => {
            const filePath = path.join(tfDir, 'main.tf');
            const original = [
                'resource "aws_s3_bucket" "data" {',
                '  bucket = "my-data-bucket"',
                '}',
                '',
            ].join('\n');
            const badFix = [
                'resource "aws_s3_bucket" "data" {',
                '      bucket     =      "my-data-bucket"',
                '}',
                '',
            ].join('\n');
            await fs.writeFile(filePath, original);

            const context = createTerraformContext(workingDir, 'terraform');
            const guard = new WorkspaceGuard(workingDir);
            const session = new EditSession(guard);

            const applied = await session.applyEdits([{
                path: 'terraform/main.tf',
                lineRange: [1, 4],
                newContent: badFix,
            }]);
            expect(applied.ok).toBe(true);

            const validator = new FixValidator(context, session.recorder, [
                new TerraformValidateStrategy(),
            ]);
            const result = await validator.validate();

            expect(result.isValid).toBe(false);
        });
    });
});
