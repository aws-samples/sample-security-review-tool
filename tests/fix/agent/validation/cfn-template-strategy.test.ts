import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CfnTemplateStrategy } from '../../../../src/fix/agent/validation/strategies/cfn-template-strategy.js';
import { ProjectContext } from '../../../../src/shared/project/project-context.js';
import { FixChange } from '../../../../src/fix/types.js';

function fakeContext(isCfn: boolean): ProjectContext {
    return {
        isCloudFormationTemplate: async () => isCfn,
    } as unknown as ProjectContext;
}

function change(filePath: string): FixChange {
    return { filePath, original: '', updated: '', startingLineNumber: 1 };
}

describe('CfnTemplateStrategy', () => {
    let workingDir: string;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cfn-strategy-'));
    });

    afterEach(async () => {
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    it('passes a well-formed JSON template', async () => {
        const filePath = path.join(workingDir, 'template.json');
        await fs.writeFile(filePath, JSON.stringify({
            Resources: { Bucket: { Type: 'AWS::S3::Bucket' } },
        }), 'utf-8');

        const results = await new CfnTemplateStrategy().validate([change(filePath)], fakeContext(true));

        expect(results).toHaveLength(1);
        expect(results[0].isValid).toBe(true);
    });

    it('fails when the Resources block is missing', async () => {
        const filePath = path.join(workingDir, 'template.json');
        await fs.writeFile(filePath, JSON.stringify({ Outputs: {} }), 'utf-8');

        const results = await new CfnTemplateStrategy().validate([change(filePath)], fakeContext(true));

        expect(results[0].isValid).toBe(false);
        expect(results[0].output).toContain('Resources');
    });

    it('fails when a resource is missing its Type', async () => {
        const filePath = path.join(workingDir, 'template.json');
        await fs.writeFile(filePath, JSON.stringify({
            Resources: { Bucket: { Properties: {} } },
        }), 'utf-8');

        const results = await new CfnTemplateStrategy().validate([change(filePath)], fakeContext(true));

        expect(results[0].isValid).toBe(false);
        expect(results[0].output).toMatch(/Type/);
    });

    it('fails when the JSON is unparseable', async () => {
        const filePath = path.join(workingDir, 'template.json');
        await fs.writeFile(filePath, '{ not: json', 'utf-8');

        const results = await new CfnTemplateStrategy().validate([change(filePath)], fakeContext(true));

        expect(results[0].isValid).toBe(false);
    });

    it('skips files the project context does not recognise as CFN', async () => {
        const filePath = path.join(workingDir, 'template.json');
        await fs.writeFile(filePath, '{}', 'utf-8');

        const results = await new CfnTemplateStrategy().validate([change(filePath)], fakeContext(false));

        expect(results).toEqual([]);
    });
});
