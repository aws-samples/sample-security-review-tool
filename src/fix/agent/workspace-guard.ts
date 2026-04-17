import * as path from 'path';

/**
 * Ensures that every path the agent touches stays inside the project root.
 * Models will sometimes emit absolute paths or ".." traversals; we normalise
 * everything to an absolute path under the root and reject anything else.
 */
export class WorkspaceGuard {
    constructor(private readonly rootFolderPath: string) {}

    public resolve(relativeOrAbsolutePath: string): string {
        const absolute = path.isAbsolute(relativeOrAbsolutePath)
            ? path.resolve(relativeOrAbsolutePath)
            : path.resolve(this.rootFolderPath, relativeOrAbsolutePath);

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
