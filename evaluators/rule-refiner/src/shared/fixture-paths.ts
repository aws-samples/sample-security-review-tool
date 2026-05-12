import * as path from 'node:path';
import * as url from 'node:url';

export function sanitizeRelativePath(relativePath: string): string {
    const normalized = path.normalize(relativePath).replace(/^(\.\.[/\\])+/, '');
    if (path.isAbsolute(normalized)) return path.basename(normalized);
    return normalized;
}

export function fixtureDirFor(
    fixturesRoot: string,
    scanner: string,
    format: string,
    checkId: string,
    variantId?: string,
): string {
    const safeCheckId = checkId.replace(/[^A-Za-z0-9_.-]/g, '_');
    const base = path.join(fixturesRoot, scanner, format, safeCheckId);
    return variantId ? path.join(base, variantId) : base;
}

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
