import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TerraformValidateStrategy } from '../../../../src/fix/agent/validation/strategies/terraform-validate-strategy.js';
import { ProjectContext } from '../../../../src/shared/project/project-context.js';
import { FixChange } from '../../../../src/fix/types.js';

function fakeContext(projects: { name: string; rootPath: string }[]): ProjectContext {
    return {
        getTerraformPlans: async () => projects.map(p => ({
            name: p.name,
            rootPath: p.rootPath,
            planJsonPath: '',
            outputFolderPath: '',
        })),
    } as unknown as ProjectContext;
}

function change(filePath: string): FixChange {
    return { filePath, original: '', updated: '', startingLineNumber: 1 };
}

function hasTerraform(): boolean {
    try {
        require('child_process').execSync('terraform version', { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

const describeTerraform = hasTerraform() ? describe : describe.skip;

describeTerraform('TerraformValidateStrategy', () => {
    let workingDir: string;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tf-validate-'));
    });

    afterEach(async () => {
        vi.restoreAllMocks();
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    it('skips non-.tf files', async () => {
        const filePath = path.join(workingDir, 'app.ts');
        await fs.writeFile(filePath, 'const x = 1;');

        const strategy = new TerraformValidateStrategy();
        const results = await strategy.validate(
            [change(filePath)],
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );

        expect(results).toEqual([]);
    });

    it('passes a well-formed .tf file with terraform fmt', async () => {
        const filePath = path.join(workingDir, 'main.tf');
        await fs.writeFile(filePath, [
            'resource "aws_s3_bucket" "example" {',
            '  bucket = "my-bucket"',
            '}',
            '',
        ].join('\n'));

        const strategy = new TerraformValidateStrategy();
        const results = await strategy.validate(
            [change(filePath)],
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );

        const fmtResult = results.find(r => r.strategy.includes('fmt'));
        expect(fmtResult).toBeDefined();
        expect(fmtResult!.isValid).toBe(true);
    });

    it('fails a poorly-formatted .tf file', async () => {
        const filePath = path.join(workingDir, 'main.tf');
        await fs.writeFile(filePath, [
            'resource "aws_s3_bucket" "example" {',
            '    bucket     =    "my-bucket"',
            '}',
        ].join('\n'));

        const strategy = new TerraformValidateStrategy();
        const results = await strategy.validate(
            [change(filePath)],
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );

        const fmtResult = results.find(r => r.strategy.includes('fmt'));
        expect(fmtResult).toBeDefined();
        expect(fmtResult!.isValid).toBe(false);
    });

    it('does not run terraform validate when .terraform dir is absent', async () => {
        const filePath = path.join(workingDir, 'main.tf');
        await fs.writeFile(filePath, [
            'resource "aws_s3_bucket" "example" {',
            '  bucket = "my-bucket"',
            '}',
            '',
        ].join('\n'));

        const strategy = new TerraformValidateStrategy();
        const results = await strategy.validate(
            [change(filePath)],
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );

        const semanticResult = results.find(r => r.strategy.startsWith('terraform-validate:validate:'));
        expect(semanticResult).toBeUndefined();
    });

    it('runs terraform validate when .terraform dir exists', async () => {
        const filePath = path.join(workingDir, 'main.tf');
        await fs.writeFile(filePath, [
            'terraform {',
            '  required_providers {}',
            '}',
            '',
            'resource "null_resource" "example" {}',
            '',
        ].join('\n'));
        await fs.mkdir(path.join(workingDir, '.terraform'), { recursive: true });

        const strategy = new TerraformValidateStrategy();
        const results = await strategy.validate(
            [change(filePath)],
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );

        const semanticResult = results.find(r => r.strategy.startsWith('terraform-validate:validate:'));
        expect(semanticResult).toBeDefined();
    });
});
