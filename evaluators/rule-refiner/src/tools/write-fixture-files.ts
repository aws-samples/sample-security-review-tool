import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import type { RefinerSession } from '../types.js';
import { sanitizeRelativePath } from '../shared/fixture-paths.js';

const NPM_INSTALL_TIMEOUT_MS = 5 * 60 * 1000;

export function createWriteFixtureFilesTool(session: RefinerSession) {
    return tool({
        name: 'write_fixture_files',
        description: 'Atomically create a fixture: clears the directory, writes all files, runs npm install if package.json exists, and initializes a git baseline commit.',
        inputSchema: z.object({
            fixtureDir: z.string().min(1).describe('Absolute path to the fixture directory.'),
            files: z.array(z.object({
                relativePath: z.string().min(1).describe('Path relative to fixtureDir.'),
                content: z.string().describe('Full file contents.'),
            })).min(1),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.fixtureDir);
            if (!resolved.startsWith(session.fixturesRoot)) {
                return { error: `fixtureDir must be under ${session.fixturesRoot}` };
            }

            clearDirectory(resolved);
            fs.mkdirSync(resolved, { recursive: true });

            const filesWritten: string[] = [];
            for (const file of input.files) {
                const safe = sanitizeRelativePath(file.relativePath);
                const absolute = path.join(resolved, safe);
                fs.mkdirSync(path.dirname(absolute), { recursive: true });
                fs.writeFileSync(absolute, file.content, 'utf8');
                filesWritten.push(safe);
            }

            const npmResult = installDeps(resolved);
            gitInit(resolved);

            const result: Record<string, JSONValue> = {
                written: true,
                filesWritten,
            };
            if (npmResult) {
                result.npmInstallResult = npmResult;
            }
            return result;
        },
    });
}

function clearDirectory(dir: string): void {
    if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

function installDeps(fixtureDir: string): JSONValue | null {
    const packageJsonPath = path.join(fixtureDir, 'package.json');
    if (!fs.existsSync(packageJsonPath)) return null;

    try {
        execSync('npm install --silent --no-audit --no-fund --prefer-offline', {
            cwd: fixtureDir,
            stdio: 'pipe',
            timeout: NPM_INSTALL_TIMEOUT_MS,
        });
        return { ok: true };
    } catch (error) {
        const anyError = error as { stdout?: unknown; stderr?: unknown; message?: unknown };
        const details = [anyError.stderr, anyError.stdout, anyError.message]
            .map(s => (s ?? '').toString().trim())
            .filter(s => s.length > 0)
            .join('\n')
            .slice(0, 2000);
        return { ok: false, error: details };
    }
}

function gitInit(fixtureDir: string): void {
    execSync('git init -q', { cwd: fixtureDir, stdio: 'ignore' });
    execSync('git add -A', { cwd: fixtureDir, stdio: 'ignore' });
    execSync('git -c user.email=refiner@srt -c user.name=Refiner commit -q -m "fixture baseline"', {
        cwd: fixtureDir,
        stdio: 'ignore',
    });
}
