import * as fs from 'fs/promises';
import * as path from 'path';
import { execSync } from 'child_process';
import { sanitizeRelativePath } from '../../shared/fixture-paths.js';

interface FixtureFile {
    relativePath: string;
    content: string;
}

export async function writeFixtureFiles(fixtureDir: string, files: FixtureFile[]): Promise<void> {
    await clearDirectory(fixtureDir);

    for (const file of files) {
        const safePath = sanitizeRelativePath(file.relativePath);
        const absolutePath = path.join(fixtureDir, safePath);
        await fs.mkdir(path.dirname(absolutePath), { recursive: true });
        await fs.writeFile(absolutePath, file.content, 'utf-8');
    }

    if (files.some(f => f.relativePath === 'package.json')) {
        execSync('npm install --silent --no-audit --no-fund --prefer-offline', {
            cwd: fixtureDir,
            timeout: 300_000,
            stdio: 'ignore',
        });
    }

    initGitBaseline(fixtureDir);
}

async function clearDirectory(dir: string): Promise<void> {
    await fs.rm(dir, { recursive: true, force: true });
    await fs.mkdir(dir, { recursive: true });
}

function initGitBaseline(dir: string): void {
    execSync('git init -q', { cwd: dir, stdio: 'ignore' });
    execSync('git add -A', { cwd: dir, stdio: 'ignore' });
    execSync('git -c user.email=refiner@srt -c user.name=Refiner commit -q -m "fixture baseline" --allow-empty', {
        cwd: dir,
        stdio: 'ignore',
    });
}
