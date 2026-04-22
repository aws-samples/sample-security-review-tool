import * as fs from 'fs/promises';
import { FixChange } from '../../types.js';

/**
 * Tracks in-memory edits proposed by the agent so the coordinator can present
 * them to the user before they are written to disk.
 *
 * Edits are accumulated per-file; the most recent proposed content wins.
 *
 * Supports a transactional apply/revert pattern used during validation: the
 * staged edits are flushed to disk, validation commands (cdk synth, tsc, etc.)
 * run against them, and then the original on-disk bytes are restored. The
 * user-facing apply happens later.
 */
export class EditRecorder {
    private readonly proposedContent = new Map<string, string>();
    private readonly originalContent = new Map<string, string>();
    private readonly originalFileExisted = new Map<string, boolean>();

    public recordOriginal(filePath: string, original: string, fileExisted: boolean = true): void {
        if (!this.originalContent.has(filePath)) {
            this.originalContent.set(filePath, original);
            this.originalFileExisted.set(filePath, fileExisted);
        }
    }

    public recordUpdate(filePath: string, updated: string): void {
        this.proposedContent.set(filePath, updated);
    }

    public toFixChanges(): FixChange[] {
        const changes: FixChange[] = [];
        for (const [filePath, updated] of this.proposedContent) {
            changes.push({
                filePath,
                original: this.originalContent.get(filePath) ?? '',
                updated,
                startingLineNumber: 1,
            });
        }
        return changes;
    }

    public getCurrentContent(filePath: string): string | undefined {
        return this.proposedContent.get(filePath);
    }

    public getOriginalContent(filePath: string): string | undefined {
        return this.originalContent.get(filePath);
    }

    public hasEdits(): boolean {
        return this.proposedContent.size > 0;
    }

    public async applyToDisk(): Promise<void> {
        for (const [filePath, content] of this.proposedContent) {
            await fs.writeFile(filePath, content, 'utf-8');
        }
    }

    public async revertToOriginal(): Promise<void> {
        for (const [filePath, original] of this.originalContent) {
            const existed = this.originalFileExisted.get(filePath) ?? true;
            if (existed) {
                await fs.writeFile(filePath, original, 'utf-8');
            } else {
                await this.deleteIfPresent(filePath);
            }
        }
    }

    private async deleteIfPresent(filePath: string): Promise<void> {
        try {
            await fs.unlink(filePath);
        } catch {
            // Nothing to revert when the file never landed on disk.
        }
    }
}
