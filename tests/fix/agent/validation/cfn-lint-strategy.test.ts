import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CfnLintStrategy } from '../../../../src/fix/agent/validation/strategies/cfn-lint-strategy.js';
import { ProjectContext } from '../../../../src/shared/project/project-context.js';
import { FixChange } from '../../../../src/fix/types.js';
import { ScannerToolManager } from '../../../../src/shared/scanner-tools/scanner-tool-manager.js';

function fakeContext(isCfn: boolean): ProjectContext {
    return {
        isCloudFormationTemplate: async () => isCfn,
    } as unknown as ProjectContext;
}

function change(filePath: string): FixChange {
    return { filePath, original: '', updated: '', startingLineNumber: 1 };
}

function cfnLintPath(): string | null {
    const candidates = [
        path.join(os.homedir(), '.srt', '.venv', 'bin', 'cfn-lint'),
        '/tmp/cfn-lint-test/bin/cfn-lint',
    ];
    for (const candidate of candidates) {
        try {
            require('fs').accessSync(candidate);
            return candidate;
        } catch {
            continue;
        }
    }
    return null;
}

const resolvedCfnLintPath = cfnLintPath();
const describeCfnLint = resolvedCfnLintPath ? describe : describe.skip;

describeCfnLint('CfnLintStrategy', () => {
    let workingDir: string;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cfn-lint-strategy-'));
        vi.spyOn(ScannerToolManager.prototype, 'isToolInstalled').mockResolvedValue(true);
        vi.spyOn(ScannerToolManager.prototype, 'getToolPath').mockReturnValue(resolvedCfnLintPath!);
    });

    afterEach(async () => {
        vi.restoreAllMocks();
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    it('passes a well-formed YAML template', async () => {
        const filePath = path.join(workingDir, 'template.yaml');
        await fs.writeFile(filePath, [
            "AWSTemplateFormatVersion: '2010-09-09'",
            'Resources:',
            '  Bucket:',
            '    Type: AWS::S3::Bucket',
        ].join('\n'), 'utf-8');

        const results = await new CfnLintStrategy().validate([change(filePath)], fakeContext(true));

        expect(results).toHaveLength(1);
        expect(results[0].isValid).toBe(true);
    });

    it('fails when a property is at the wrong nesting level', async () => {
        const filePath = path.join(workingDir, 'template.yaml');
        await fs.writeFile(filePath, [
            "AWSTemplateFormatVersion: '2010-09-09'",
            'Resources:',
            '  AppBucket:',
            '    Type: AWS::S3::Bucket',
            '    Properties:',
            '      BucketName: my-bucket',
            '      LifecycleConfiguration:',
            '        Rules:',
            '          - Id: TransitionToIA',
            '            Status: Enabled',
            '      Transitions:',
            '        - StorageClass: STANDARD_IA',
            '          TransitionInDays: 30',
        ].join('\n'), 'utf-8');

        const results = await new CfnLintStrategy().validate([change(filePath)], fakeContext(true));

        expect(results).toHaveLength(1);
        expect(results[0].isValid).toBe(false);
        expect(results[0].output).toContain('Transitions');
    });

    it('skips non-CFN files', async () => {
        const filePath = path.join(workingDir, 'app.ts');
        await fs.writeFile(filePath, 'const x = 1;', 'utf-8');

        const results = await new CfnLintStrategy().validate([change(filePath)], fakeContext(false));

        expect(results).toEqual([]);
    });

    it('throws when cfn-lint is not installed', async () => {
        vi.spyOn(ScannerToolManager.prototype, 'isToolInstalled').mockResolvedValue(false);

        const filePath = path.join(workingDir, 'template.yaml');
        await fs.writeFile(filePath, [
            "AWSTemplateFormatVersion: '2010-09-09'",
            'Resources:',
            '  Bucket:',
            '    Type: AWS::S3::Bucket',
        ].join('\n'), 'utf-8');

        await expect(
            new CfnLintStrategy().validate([change(filePath)], fakeContext(true)),
        ).rejects.toThrow('cfn-lint is not installed');
    });
});
