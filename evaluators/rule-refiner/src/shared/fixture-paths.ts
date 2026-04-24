import * as path from 'node:path';

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
