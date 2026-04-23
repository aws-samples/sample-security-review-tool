import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CodeApplicator } from '../../../src/fix/code-manipulation/code-applicator.js';
import { ProjectContext } from '../../../src/shared/project/project-context.js';
import { IssueUpdater } from '../../../src/fix/issues/issue-updater.js';
import { Fix } from '../../../src/fix/types.js';
import { ScanResult } from '../../../src/assess/scanning/types.js';

function fakeContext(isCfn: boolean, isCdk: boolean): ProjectContext {
    return {
        isCloudFormationTemplate: async () => isCfn,
        isCdkProject: async () => isCdk,
    } as unknown as ProjectContext;
}

function fakeIssueUpdater(): IssueUpdater {
    return { markAsFixed: vi.fn() } as unknown as IssueUpdater;
}

const ISSUE: ScanResult = {
    source: 'security-matrix',
    check_id: 'S3-008',
    priority: 'HIGH',
    path: 'template.yaml',
    issue: 'S3 bucket lacks lifecycle policy',
    fix: 'Add a LifecycleConfiguration',
    status: 'Open',
};

describe('CodeApplicator', () => {
    let workingDir: string;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'code-applicator-'));
    });

    afterEach(async () => {
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    it('writes full-file replacement directly without re-indentation', async () => {
        const filePath = path.join(workingDir, 'template.yaml');
        const original = [
            "AWSTemplateFormatVersion: '2010-09-09'",
            'Resources:',
            '  AppBucket:',
            '    Type: AWS::S3::Bucket',
            '    Properties:',
            '      BucketName: my-app-bucket',
        ].join('\n');

        const updated = [
            "AWSTemplateFormatVersion: '2010-09-09'",
            'Resources:',
            '  AppBucket:',
            '    Type: AWS::S3::Bucket',
            '    Properties:',
            '      BucketName: my-app-bucket',
            '      LifecycleConfiguration:',
            '        Rules:',
            '          - Id: TransitionToIA',
            '            Status: Enabled',
            '            Transitions:',
            '              - StorageClass: STANDARD_IA',
            '                TransitionInDays: 30',
        ].join('\n');

        await fs.writeFile(filePath, original, 'utf-8');

        const fix: Fix = {
            changes: [{ filePath, original, updated, startingLineNumber: 1 }],
            comments: 'test',
        };

        const applicator = new CodeApplicator(fakeContext(true, false), fakeIssueUpdater());
        await applicator.applyFix(ISSUE, fix);

        const result = await fs.readFile(filePath, 'utf-8');
        expect(result).toBe(updated);
    });
});
