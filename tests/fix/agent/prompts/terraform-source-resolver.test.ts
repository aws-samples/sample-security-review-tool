import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TerraformSourceResolver } from '../../../../src/fix/agent/prompts/terraform-source-resolver.js';
import { ProjectContext } from '../../../../src/shared/project/project-context.js';
import { ScanResult } from '../../../../src/assess/scanning/types.js';

function fakeContext(projects: { name: string; rootPath: string }[]): ProjectContext {
    return {
        getTerraformPlans: async () => projects.map(p => ({
            name: p.name,
            rootPath: p.rootPath,
            outputFolderPath: '',
        })),
    } as unknown as ProjectContext;
}

function terraformIssue(overrides: Partial<ScanResult> = {}): ScanResult {
    return {
        source: 'terraform-matrix',
        path: 'terraform',
        resourceType: 'aws_s3_bucket',
        resourceName: 'aws_s3_bucket.my_bucket',
        issue: 'Bucket does not have versioning enabled',
        fix: 'Enable versioning',
        priority: 'HIGH',
        check_id: 'S3-001',
        status: 'Open',
        ...overrides,
    } as ScanResult;
}

describe('TerraformSourceResolver', () => {
    let workingDir: string;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tf-resolver-'));
    });

    afterEach(async () => {
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    it('resolves a simple resource to its file and line', async () => {
        const tfContent = [
            'resource "aws_s3_bucket" "my_bucket" {',
            '  bucket = "my-bucket"',
            '}',
        ].join('\n');
        await fs.writeFile(path.join(workingDir, 'main.tf'), tfContent);

        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue());

        expect(result).not.toBeNull();
        expect(result!.path).toBe(path.join(workingDir, 'main.tf'));
        expect(result!.focusLine).toBe(1);
        expect(result!.content).toBe(tfContent);
    });

    it('finds a resource that is not on the first line', async () => {
        const tfContent = [
            'resource "aws_vpc" "main" {',
            '  cidr_block = "10.0.0.0/16"',
            '}',
            '',
            'resource "aws_s3_bucket" "my_bucket" {',
            '  bucket = "my-bucket"',
            '}',
        ].join('\n');
        await fs.writeFile(path.join(workingDir, 'main.tf'), tfContent);

        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue());

        expect(result).not.toBeNull();
        expect(result!.focusLine).toBe(5);
    });

    it('searches across multiple .tf files', async () => {
        await fs.writeFile(path.join(workingDir, 'vpc.tf'), [
            'resource "aws_vpc" "main" {',
            '  cidr_block = "10.0.0.0/16"',
            '}',
        ].join('\n'));
        await fs.writeFile(path.join(workingDir, 'storage.tf'), [
            'resource "aws_s3_bucket" "my_bucket" {',
            '  bucket = "my-bucket"',
            '}',
        ].join('\n'));

        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue());

        expect(result).not.toBeNull();
        expect(result!.path).toBe(path.join(workingDir, 'storage.tf'));
        expect(result!.focusLine).toBe(1);
    });

    it('strips module prefix from resource address', async () => {
        const tfContent = [
            'resource "aws_s3_bucket" "data" {',
            '  bucket = "data-bucket"',
            '}',
        ].join('\n');
        await fs.writeFile(path.join(workingDir, 'main.tf'), tfContent);

        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue({
            resourceName: 'module.storage.aws_s3_bucket.data',
        }));

        expect(result).not.toBeNull();
        expect(result!.focusLine).toBe(1);
    });

    it('strips index suffix from resource address', async () => {
        const tfContent = [
            'resource "aws_s3_bucket" "logs" {',
            '  bucket = "logs-bucket"',
            '}',
        ].join('\n');
        await fs.writeFile(path.join(workingDir, 'main.tf'), tfContent);

        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue({
            resourceName: 'aws_s3_bucket.logs[0]',
        }));

        expect(result).not.toBeNull();
        expect(result!.focusLine).toBe(1);
    });

    it('returns null when resource is not found', async () => {
        await fs.writeFile(path.join(workingDir, 'main.tf'), [
            'resource "aws_vpc" "main" {',
            '  cidr_block = "10.0.0.0/16"',
            '}',
        ].join('\n'));

        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue());

        expect(result).toBeNull();
    });

    it('returns null when project name does not match', async () => {
        await fs.writeFile(path.join(workingDir, 'main.tf'), [
            'resource "aws_s3_bucket" "my_bucket" {',
            '  bucket = "my-bucket"',
            '}',
        ].join('\n'));

        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'other-project', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue());

        expect(result).toBeNull();
    });

    it('returns null when resourceName is missing', async () => {
        const resolver = new TerraformSourceResolver(
            fakeContext([{ name: 'terraform', rootPath: workingDir }]),
        );
        const result = await resolver.resolve(terraformIssue({ resourceName: undefined }));

        expect(result).toBeNull();
    });

    describe('parseResourceAddress', () => {
        it('parses simple address', () => {
            const resolver = new TerraformSourceResolver(
                fakeContext([]),
            );
            expect(resolver.parseResourceAddress('aws_s3_bucket.my_bucket'))
                .toEqual({ type: 'aws_s3_bucket', name: 'my_bucket' });
        });

        it('strips single module prefix', () => {
            const resolver = new TerraformSourceResolver(fakeContext([]));
            expect(resolver.parseResourceAddress('module.storage.aws_s3_bucket.data'))
                .toEqual({ type: 'aws_s3_bucket', name: 'data' });
        });

        it('strips nested module prefixes', () => {
            const resolver = new TerraformSourceResolver(fakeContext([]));
            expect(resolver.parseResourceAddress('module.infra.module.storage.aws_s3_bucket.data'))
                .toEqual({ type: 'aws_s3_bucket', name: 'data' });
        });

        it('strips index suffix', () => {
            const resolver = new TerraformSourceResolver(fakeContext([]));
            expect(resolver.parseResourceAddress('aws_s3_bucket.logs[0]'))
                .toEqual({ type: 'aws_s3_bucket', name: 'logs' });
        });

        it('strips both module prefix and index suffix', () => {
            const resolver = new TerraformSourceResolver(fakeContext([]));
            expect(resolver.parseResourceAddress('module.foo.aws_subnet.private[2]'))
                .toEqual({ type: 'aws_subnet', name: 'private' });
        });
    });
});
