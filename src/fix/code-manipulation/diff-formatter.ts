import chalk from 'chalk';
import { diffTrimmedLines } from 'diff';

export class DiffFormatter {
    public formatDiff(lineNumber: number, original: string, fixed: string): string[] {
        const diff = diffTrimmedLines(original, fixed);
        const currentLine = { current: lineNumber };
        const formattedLines: string[] = [];

        diff.forEach(changeObject => {
            if (changeObject.added) {
                changeObject.value.replace(/\r?\n$/, '').split(/\r?\n/).forEach(line => {
                    formattedLines.push(`${currentLine.current}: ${chalk.bgRgb(0, 100, 0)(line)}`);
                    currentLine.current++;
                });
            } else if (changeObject.removed) {
                changeObject.value.replace(/\r?\n$/, '').split(/\r?\n/).forEach(line => {
                    formattedLines.push(`${currentLine.current}: ${chalk.bgRgb(139, 0, 0)(line)}`);
                });
            } else {
                changeObject.value.replace(/\r?\n$/, '').split(/\r?\n/).forEach(line => {
                    formattedLines.push(chalk.white(`${currentLine.current}: ${line}`));
                    currentLine.current++;
                });
            }
        });

        return formattedLines;
    }
}
