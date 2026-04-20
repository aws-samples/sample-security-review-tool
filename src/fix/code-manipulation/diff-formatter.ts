import chalk from 'chalk';
import { diffTrimmedLines } from 'diff';

const CONTEXT_LINES = 3;

type LineKind = 'added' | 'removed' | 'context';

interface DiffLine {
    kind: LineKind;
    text: string;
    displayLineNumber: number;
}

export class DiffFormatter {
    public formatDiff(lineNumber: number, original: string, fixed: string): string[] {
        const diffLines = this.buildDiffLines(lineNumber, original, fixed);

        if (!this.hasChanges(diffLines)) {
            return [];
        }

        const hunks = this.buildHunks(diffLines);
        return this.renderHunks(hunks);
    }

    private buildDiffLines(startingLineNumber: number, original: string, fixed: string): DiffLine[] {
        const changes = diffTrimmedLines(original, fixed);
        const diffLines: DiffLine[] = [];
        let originalLineNumber = startingLineNumber;
        let updatedLineNumber = startingLineNumber;

        for (const change of changes) {
            const lines = change.value.replace(/\r?\n$/, '').split(/\r?\n/);

            for (const text of lines) {
                if (change.added) {
                    diffLines.push({ kind: 'added', text, displayLineNumber: updatedLineNumber });
                    updatedLineNumber++;
                } else if (change.removed) {
                    diffLines.push({ kind: 'removed', text, displayLineNumber: originalLineNumber });
                    originalLineNumber++;
                } else {
                    diffLines.push({ kind: 'context', text, displayLineNumber: updatedLineNumber });
                    originalLineNumber++;
                    updatedLineNumber++;
                }
            }
        }

        return diffLines;
    }

    private hasChanges(diffLines: DiffLine[]): boolean {
        return diffLines.some(line => line.kind !== 'context');
    }

    private buildHunks(diffLines: DiffLine[]): DiffLine[][] {
        const includedIndices = this.findIncludedIndices(diffLines);
        const hunks: DiffLine[][] = [];
        let currentHunk: DiffLine[] = [];
        let previousIndex = -2;

        for (const index of includedIndices) {
            if (index !== previousIndex + 1 && currentHunk.length > 0) {
                hunks.push(currentHunk);
                currentHunk = [];
            }
            currentHunk.push(diffLines[index]);
            previousIndex = index;
        }

        if (currentHunk.length > 0) {
            hunks.push(currentHunk);
        }

        return hunks;
    }

    private findIncludedIndices(diffLines: DiffLine[]): number[] {
        const included = new Set<number>();

        diffLines.forEach((line, index) => {
            if (line.kind === 'context') {
                return;
            }
            const start = Math.max(0, index - CONTEXT_LINES);
            const end = Math.min(diffLines.length - 1, index + CONTEXT_LINES);
            for (let i = start; i <= end; i++) {
                included.add(i);
            }
        });

        return [...included].sort((a, b) => a - b);
    }

    private renderHunks(hunks: DiffLine[][]): string[] {
        const output: string[] = [];
        const lineNumberWidth = this.computeLineNumberWidth(hunks);

        hunks.forEach((hunk, hunkIndex) => {
            if (hunkIndex > 0) {
                output.push(chalk.dim('   ...'));
            }

            output.push(chalk.dim(`@@ line ${this.hunkStartLineNumber(hunk)} @@`));

            for (const line of hunk) {
                output.push(this.renderLine(line, lineNumberWidth));
            }
        });

        return output;
    }

    private hunkStartLineNumber(hunk: DiffLine[]): number {
        const firstContextOrAdded = hunk.find(line => line.kind !== 'removed');
        return (firstContextOrAdded ?? hunk[0]).displayLineNumber;
    }

    private computeLineNumberWidth(hunks: DiffLine[][]): number {
        let maxLineNumber = 0;
        for (const hunk of hunks) {
            for (const line of hunk) {
                if (line.displayLineNumber > maxLineNumber) {
                    maxLineNumber = line.displayLineNumber;
                }
            }
        }
        return String(maxLineNumber).length;
    }

    private renderLine(line: DiffLine, lineNumberWidth: number): string {
        const lineNumberLabel = `${String(line.displayLineNumber).padStart(lineNumberWidth, ' ')}: `;

        if (line.kind === 'added') {
            return `${lineNumberLabel}${chalk.bgRgb(0, 100, 0)(`+ ${line.text}`)}`;
        }
        if (line.kind === 'removed') {
            return `${lineNumberLabel}${chalk.bgRgb(139, 0, 0)(`- ${line.text}`)}`;
        }
        return chalk.white(`${lineNumberLabel}  ${line.text}`);
    }
}
