import * as fs from 'fs/promises';
import { FixChange } from '../types.js';
import { ValidationState } from './validation/validation-state.js';

/**
 * Tracks in-memory edits proposed by the agent's editing tools so that the
 * FixCoordinator can present them to the user before they are written to disk.
 *
 * Edits are accumulated per-file; the most recent proposed content wins.
 *
 * Supports a transactional flush/revert pattern used by the ValidateFixTool:
 * apply the staged edits to disk, run validation commands (cdk synth, tsc,
 * etc.), and then restore the original on-disk bytes regardless of the
 * outcome. The user-facing apply happens later, via the FixCoordinator.
 */
export class EditRecorder {
    private readonly proposedContent = new Map<string, string>();
    private readonly originalContent = new Map<string, string>();
    private readonly originalFileExisted = new Map<string, boolean>();

    constructor(private readonly validationState?: ValidationState) {}

    public recordOriginal(filePath: string, original: string, fileExisted: boolean = true): void {
        if (!this.originalContent.has(filePath)) {
            this.originalContent.set(filePath, original);
            this.originalFileExisted.set(filePath, fileExisted);
        }
    }

    public recordUpdate(filePath: string, updated: string): void {
        this.proposedContent.set(filePath, updated);
        this.validationState?.bumpEditVersion();
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
