import * as path from 'path';

/**
 * Ensures that every path the agent touches stays inside the project root.
 *
 * Models emit paths with varying conventions (forward slashes, backslashes,
 * occasionally absolute paths). We normalise separators, resolve to an
 * absolute path rooted at the project root, and reject anything that escapes
 * the root via "..".
 */
export class WorkspaceGuard {
    constructor(private readonly rootFolderPath: string) {}

    public resolve(relativeOrAbsolutePath: string): string {
        const normalised = relativeOrAbsolutePath.replace(/\\/g, '/');

        const absolute = path.isAbsolute(normalised)
            ? path.resolve(normalised)
            : path.resolve(this.rootFolderPath, normalised);

        const relative = path.relative(this.rootFolderPath, absolute);

        if (relative.startsWith('..') || path.isAbsolute(relative)) {
            throw new Error(`Path is outside the project root: ${relativeOrAbsolutePath}`);
        }

        return absolute;
    }

    public toRelative(absolutePath: string): string {
        return path.relative(this.rootFolderPath, absolutePath);
    }
}
