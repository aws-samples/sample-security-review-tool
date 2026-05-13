import * as path from 'node:path';
import * as url from 'node:url';

export function srtRepoRoot(): string {
    const moduleDir = path.dirname(url.fileURLToPath(import.meta.url));
    return path.resolve(moduleDir, '..', '..', '..', '..');
}

export function requirementsDir(): string {
    const moduleDir = path.dirname(url.fileURLToPath(import.meta.url));
    return path.resolve(moduleDir, '..', '..', 'requirements');
}

export function requirementsPathFor(checkId: string, format: string): string {
    const safeCheckId = checkId.replace(/[^A-Za-z0-9_.-]/g, '_');
    return path.join(requirementsDir(), safeCheckId, `${format}.requirements.json`);
}
