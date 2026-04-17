import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { DsrMigrator } from '../../../src/shared/project/dsr-migrator.js';

describe('DsrMigrator', () => {
    let tempRoot: string;

    beforeEach(async () => {
        tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'dsr-migrator-'));
    });

    afterEach(async () => {
        await fsp.rm(tempRoot, { recursive: true, force: true });
    });

    async function writeFile(relativePath: string, contents: string): Promise<void> {
        const fullPath = path.join(tempRoot, relativePath);
        await fsp.mkdir(path.dirname(fullPath), { recursive: true });
        await fsp.writeFile(fullPath, contents);
    }

    it('renames .dsr to .srt and preserves contents when .srt does not exist', async () => {
        await writeFile('.dsr/issues.json', '[{"id":"1"}]');
        await writeFile('.dsr/settings.json', '{"LICENSE":"Apache-2.0"}');
        await writeFile('.dsr/threat-models/stack.md', '# threat model');

        const migrator = new DsrMigrator(tempRoot);
        const didMigrate = await migrator.migrate();

        expect(didMigrate).toBe(true);
        expect(fs.existsSync(path.join(tempRoot, '.dsr'))).toBe(false);
        expect(fs.existsSync(path.join(tempRoot, '.srt'))).toBe(true);
        expect(await fsp.readFile(path.join(tempRoot, '.srt/issues.json'), 'utf8')).toBe('[{"id":"1"}]');
        expect(await fsp.readFile(path.join(tempRoot, '.srt/settings.json'), 'utf8')).toBe('{"LICENSE":"Apache-2.0"}');
        expect(await fsp.readFile(path.join(tempRoot, '.srt/threat-models/stack.md'), 'utf8')).toBe('# threat model');
    });

    it('is a no-op when .dsr does not exist', async () => {
        const migrator = new DsrMigrator(tempRoot);
        const didMigrate = await migrator.migrate();

        expect(didMigrate).toBe(false);
        expect(fs.existsSync(path.join(tempRoot, '.srt'))).toBe(false);
    });

    it('does not touch .dsr when .srt already exists', async () => {
        await writeFile('.dsr/issues.json', '[{"id":"old"}]');
        await writeFile('.srt/issues.json', '[{"id":"current"}]');

        const migrator = new DsrMigrator(tempRoot);
        const didMigrate = await migrator.migrate();

        expect(didMigrate).toBe(false);
        expect(fs.existsSync(path.join(tempRoot, '.dsr'))).toBe(true);
        expect(await fsp.readFile(path.join(tempRoot, '.srt/issues.json'), 'utf8')).toBe('[{"id":"current"}]');
        expect(await fsp.readFile(path.join(tempRoot, '.dsr/issues.json'), 'utf8')).toBe('[{"id":"old"}]');
    });

    it('is a no-op when .dsr is a file rather than a directory', async () => {
        await writeFile('.dsr', 'not a directory');

        const migrator = new DsrMigrator(tempRoot);
        const didMigrate = await migrator.migrate();

        expect(didMigrate).toBe(false);
        expect(fs.existsSync(path.join(tempRoot, '.srt'))).toBe(false);
        expect(fs.statSync(path.join(tempRoot, '.dsr')).isFile()).toBe(true);
    });

    it('reports progress messages when migration occurs', async () => {
        await writeFile('.dsr/issues.json', '[]');
        const progressMessages: string[] = [];

        const migrator = new DsrMigrator(tempRoot, (msg) => progressMessages.push(msg));
        await migrator.migrate();

        expect(progressMessages.length).toBe(2);
        expect(progressMessages[0]).toContain('Migrating');
        expect(progressMessages[1]).toContain('Migrated');
    });

    it('does not report progress when no migration is needed', async () => {
        const progressMessages: string[] = [];

        const migrator = new DsrMigrator(tempRoot, (msg) => progressMessages.push(msg));
        await migrator.migrate();

        expect(progressMessages).toEqual([]);
    });
});
