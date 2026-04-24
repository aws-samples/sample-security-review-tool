import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EditSession, EditInput } from '../../../../src/fix/agent/staging/edit-session.js';
import { WorkspaceGuard } from '../../../../src/fix/agent/staging/workspace-guard.js';

describe('EditSession', () => {
    let workingDir: string;
    let session: EditSession;

    beforeEach(async () => {
        workingDir = await fs.mkdtemp(path.join(os.tmpdir(), 'edit-session-'));
        const guard = new WorkspaceGuard(workingDir);
        session = new EditSession(guard);
    });

    afterEach(async () => {
        await fs.rm(workingDir, { recursive: true, force: true });
    });

    async function writeFile(relativePath: string, content: string): Promise<void> {
        const absolute = path.join(workingDir, relativePath);
        await fs.mkdir(path.dirname(absolute), { recursive: true });
        await fs.writeFile(absolute, content, 'utf-8');
    }

    function getUpdatedContent(relativePath: string): string | undefined {
        const absolute = path.join(workingDir, relativePath);
        const changes = session.recorder.toFixChanges();
        return changes.find(c => c.filePath === absolute)?.updated;
    }

    describe('single edit per file', () => {
        it('replaces a line range', async () => {
            await writeFile('file.ts', 'line1\nline2\nline3\nline4\nline5');

            const result = await session.applyEdits([{
                path: 'file.ts',
                lineRange: [2, 3],
                newContent: 'replaced2\nreplaced3',
            }]);

            expect(result).toEqual({ ok: true });
            expect(getUpdatedContent('file.ts')).toBe('line1\nreplaced2\nreplaced3\nline4\nline5');
        });

        it('inserts before a line with [n, n-1]', async () => {
            await writeFile('file.ts', 'line1\nline2\nline3');

            const result = await session.applyEdits([{
                path: 'file.ts',
                lineRange: [2, 1],
                newContent: 'inserted',
            }]);

            expect(result).toEqual({ ok: true });
            expect(getUpdatedContent('file.ts')).toBe('line1\ninserted\nline2\nline3');
        });
    });

    describe('multiple edits to the same file — offset translation', () => {
        it('adjusts second edit when first edit adds lines', async () => {
            // Simulates the DDB-002 scenario: edit 1 adds an import line,
            // edit 2 targets a line further down using original line numbers.
            await writeFile('file.ts', [
                'import { A } from "a";',       // 1
                'import { B } from "b";',       // 2
                '',                              // 3
                'class Stack {',                 // 4
                '  constructor() {',             // 5
                '    const table = new Table();', // 6
                '    });',                       // 7
                '  }',                           // 8
                '}',                             // 9
            ].join('\n'));

            const result = await session.applyEdits([
                {
                    path: 'file.ts',
                    lineRange: [1, 2],
                    newContent: 'import { A } from "a";\nimport { B } from "b";\nimport { C } from "c";',
                },
                {
                    path: 'file.ts',
                    lineRange: [8, 7],
                    newContent: '    const trail = new Trail();',
                },
            ]);

            expect(result).toEqual({ ok: true });
            const lines = getUpdatedContent('file.ts')!.split('\n');
            expect(lines[0]).toBe('import { A } from "a";');
            expect(lines[1]).toBe('import { B } from "b";');
            expect(lines[2]).toBe('import { C } from "c";');
            // The insert-before-8 should land between '    });' and '  }' in the original,
            // which is now between lines 8 and 9 in the modified content.
            expect(lines[7]).toBe('    });');
            expect(lines[8]).toBe('    const trail = new Trail();');
            expect(lines[9]).toBe('  }');
        });

        it('adjusts second edit when first edit removes lines', async () => {
            await writeFile('file.ts', [
                'line1',  // 1
                'line2',  // 2
                'line3',  // 3
                'line4',  // 4
                'line5',  // 5
                'line6',  // 6
            ].join('\n'));

            const result = await session.applyEdits([
                {
                    path: 'file.ts',
                    lineRange: [2, 3],
                    newContent: 'collapsed',
                },
                {
                    path: 'file.ts',
                    lineRange: [5, 5],
                    newContent: 'replaced5',
                },
            ]);

            expect(result).toEqual({ ok: true });
            // After edit 1: line1, collapsed, line4, line5, line6 (5 lines, offset -1)
            // Edit 2 targets original line 5 → adjusted to line 4
            expect(getUpdatedContent('file.ts')).toBe('line1\ncollapsed\nline4\nreplaced5\nline6');
        });

        it('handles insert + replacement combo', async () => {
            await writeFile('file.ts', [
                'line1',  // 1
                'line2',  // 2
                'line3',  // 3
                'line4',  // 4
            ].join('\n'));

            const result = await session.applyEdits([
                {
                    path: 'file.ts',
                    lineRange: [2, 1],
                    newContent: 'insertedA\ninsertedB',
                },
                {
                    path: 'file.ts',
                    lineRange: [4, 4],
                    newContent: 'replaced4',
                },
            ]);

            expect(result).toEqual({ ok: true });
            // After insert before line 2: line1, insertedA, insertedB, line2, line3, line4 (+2 offset)
            // Edit 2 targets original line 4 → adjusted to line 6
            expect(getUpdatedContent('file.ts')).toBe('line1\ninsertedA\ninsertedB\nline2\nline3\nreplaced4');
        });

        it('handles three edits with cumulative offset', async () => {
            await writeFile('file.ts', [
                'a',  // 1
                'b',  // 2
                'c',  // 3
                'd',  // 4
                'e',  // 5
                'f',  // 6
            ].join('\n'));

            const result = await session.applyEdits([
                { path: 'file.ts', lineRange: [1, 1], newContent: 'A1\nA2' },
                { path: 'file.ts', lineRange: [3, 3], newContent: 'C' },
                { path: 'file.ts', lineRange: [5, 6], newContent: 'EF' },
            ]);

            expect(result).toEqual({ ok: true });
            // Edit 1: replace line 1 with 2 lines → offset +1
            // Edit 2: replace line 3 (adjusted to 4) with 1 line → offset stays +1
            // Edit 3: replace lines 5-6 (adjusted to 6-7) with 1 line → offset 0
            expect(getUpdatedContent('file.ts')).toBe('A1\nA2\nb\nC\nd\nEF');
        });
    });

    describe('edits sorted regardless of input order', () => {
        it('produces the same result when edits are given in reverse order', async () => {
            await writeFile('file.ts', 'line1\nline2\nline3\nline4\nline5');

            const result = await session.applyEdits([
                { path: 'file.ts', lineRange: [4, 4], newContent: 'FOUR' },
                { path: 'file.ts', lineRange: [1, 2], newContent: 'ONE-TWO\nEXTRA' },
            ]);

            expect(result).toEqual({ ok: true });
            // Edit [1,2] adds 1 line (2→2 lines, net 0 actually: replaces 2 with 2). Wait:
            // Replace lines 1-2 (2 lines) with "ONE-TWO\nEXTRA" (2 lines) → offset 0
            // Edit [4,4]: offset 0, so line 4 stays line 4
            expect(getUpdatedContent('file.ts')).toBe('ONE-TWO\nEXTRA\nline3\nFOUR\nline5');
        });
    });

    describe('overlapping edits', () => {
        it('rejects edits with overlapping line ranges', async () => {
            await writeFile('file.ts', 'line1\nline2\nline3\nline4\nline5');

            const result = await session.applyEdits([
                { path: 'file.ts', lineRange: [2, 4], newContent: 'a' },
                { path: 'file.ts', lineRange: [3, 5], newContent: 'b' },
            ]);

            expect(result).toEqual(expect.objectContaining({ ok: false }));
            expect((result as { reason: string }).reason).toContain('Overlapping');
        });

        it('rejects edits where second starts at end of first', async () => {
            await writeFile('file.ts', 'line1\nline2\nline3\nline4\nline5');

            const result = await session.applyEdits([
                { path: 'file.ts', lineRange: [2, 3], newContent: 'a' },
                { path: 'file.ts', lineRange: [3, 4], newContent: 'b' },
            ]);

            expect(result).toEqual(expect.objectContaining({ ok: false }));
            expect((result as { reason: string }).reason).toContain('Overlapping');
        });
    });

    describe('edits to different files', () => {
        it('applies independently without offset interference', async () => {
            await writeFile('a.ts', 'a1\na2\na3');
            await writeFile('b.ts', 'b1\nb2\nb3');

            const result = await session.applyEdits([
                { path: 'a.ts', lineRange: [1, 1], newContent: 'A1\nA1B' },
                { path: 'b.ts', lineRange: [2, 2], newContent: 'B2' },
            ]);

            expect(result).toEqual({ ok: true });
            expect(getUpdatedContent('a.ts')).toBe('A1\nA1B\na2\na3');
            expect(getUpdatedContent('b.ts')).toBe('b1\nB2\nb3');
        });
    });

    describe('new file creation', () => {
        it('creates a new file with [1, 0]', async () => {
            const result = await session.applyEdits([{
                path: 'new-file.ts',
                lineRange: [1, 0],
                newContent: 'content line 1\ncontent line 2',
            }]);

            expect(result).toEqual({ ok: true });
            expect(getUpdatedContent('new-file.ts')).toBe('content line 1\ncontent line 2');
        });
    });

    describe('empty edits', () => {
        it('rejects an empty edits array', async () => {
            const result = await session.applyEdits([]);
            expect(result).toEqual(expect.objectContaining({ ok: false }));
        });
    });
});
