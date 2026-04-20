import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EditRecorder } from '../../../../src/fix/agent/edit-recorder.js';
import { FixValidator } from '../../../../src/fix/agent/validation/fix-validator.js';
import { StrategyResult, ValidationStrategy } from '../../../../src/fix/agent/validation/types.js';
import { ProjectContext } from '../../../../src/shared/project/project-context.js';

class StubStrategy implements ValidationStrategy {
    public readonly name = 'stub';
    constructor(private readonly result: StrategyResult) {}
    public async validate(): Promise<StrategyResult[]> {
        return [this.result];
    }
}

describe('FixValidator', () => {
    let workingDir: string;
    let filePath: string;
    let context: ProjectContext;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'fix-validator-'));
        filePath = path.join(workingDir, 'file.ts');
        await fs.writeFile(filePath, 'original', 'utf-8');
        context = { getProjectRootFolderPath: () => workingDir } as unknown as ProjectContext;
    });

    afterEach(async () => {
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    it('returns isValid=true when there are no staged edits', async () => {
        const recorder = new EditRecorder();
        const validator = new FixValidator(context, recorder, []);

        const result = await validator.validate();

        expect(result.isValid).toBe(true);
        expect(result.checks).toEqual([]);
    });

    it('applies edits, runs strategies, and reverts the disk on success', async () => {
        const recorder = new EditRecorder();
        recorder.recordOriginal(filePath, 'original');
        recorder.recordUpdate(filePath, 'updated');

        const validator = new FixValidator(context, recorder, [
            new StubStrategy({ strategy: 'stub', isValid: true }),
        ]);

        const result = await validator.validate();

        expect(result.isValid).toBe(true);
        expect(await fs.readFile(filePath, 'utf-8')).toBe('original');
    });

    it('reports the failing check and still reverts the disk on failure', async () => {
        const recorder = new EditRecorder();
        recorder.recordOriginal(filePath, 'original');
        recorder.recordUpdate(filePath, 'broken');

        const validator = new FixValidator(context, recorder, [
            new StubStrategy({ strategy: 'stub', isValid: false, output: 'broken syntax' }),
        ]);

        const result = await validator.validate();

        expect(result.isValid).toBe(false);
        expect(result.failingCheck?.output).toBe('broken syntax');
        expect(await fs.readFile(filePath, 'utf-8')).toBe('original');
    });
});
