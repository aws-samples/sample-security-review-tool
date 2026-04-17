import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Migrates legacy `.dsr/` artifact folders (from the predecessor Deliverable
 * Security Review tool) to the current `.srt/` folder location.
 *
 * The migration is a one-time rename so that all downstream components can
 * continue to operate against a single, consistent `.srt/` path.
 */
export class DsrMigrator {
    private static readonly LEGACY_FOLDER_NAME = '.dsr';
    private static readonly CURRENT_FOLDER_NAME = '.srt';

    constructor(
        private readonly projectRootFolderPath: string,
        private readonly onProgress: (progress: string) => void = () => { }
    ) { }

    public async migrate(): Promise<boolean> {
        const legacyPath = path.join(this.projectRootFolderPath, DsrMigrator.LEGACY_FOLDER_NAME);
        const currentPath = path.join(this.projectRootFolderPath, DsrMigrator.CURRENT_FOLDER_NAME);

        if (!(await this.isDirectory(legacyPath))) {
            return false;
        }

        if (await this.exists(currentPath)) {
            // `.srt/` is authoritative when both exist; leave `.dsr/` untouched.
            return false;
        }

        this.onProgress(`  › Migrating artifacts from ${DsrMigrator.LEGACY_FOLDER_NAME} to ${DsrMigrator.CURRENT_FOLDER_NAME}...`);

        try {
            await fs.rename(legacyPath, currentPath);
        } catch (error) {
            // `fs.rename` can fail with EXDEV across filesystem/volume boundaries.
            // Fall back to a recursive copy followed by removal of the source.
            await this.copyRecursive(legacyPath, currentPath);
            await fs.rm(legacyPath, { recursive: true, force: true });
        }

        this.onProgress(`  ✔ Migrated artifacts from ${DsrMigrator.LEGACY_FOLDER_NAME} to ${DsrMigrator.CURRENT_FOLDER_NAME}`);
        return true;
    }

    private async exists(candidatePath: string): Promise<boolean> {
        try {
            await fs.access(candidatePath);
            return true;
        } catch {
            return false;
        }
    }

    private async isDirectory(candidatePath: string): Promise<boolean> {
        try {
            const stats = await fs.stat(candidatePath);
            return stats.isDirectory();
        } catch {
            return false;
        }
    }

    private async copyRecursive(source: string, destination: string): Promise<void> {
        await fs.mkdir(destination, { recursive: true });
        const entries = await fs.readdir(source, { withFileTypes: true });

        for (const entry of entries) {
            const sourcePath = path.join(source, entry.name);
            const destinationPath = path.join(destination, entry.name);

            if (entry.isDirectory()) {
                await this.copyRecursive(sourcePath, destinationPath);
            } else if (entry.isSymbolicLink()) {
                const linkTarget = await fs.readlink(sourcePath);
                await fs.symlink(linkTarget, destinationPath);
            } else {
                await fs.copyFile(sourcePath, destinationPath);
            }
        }
    }
}
