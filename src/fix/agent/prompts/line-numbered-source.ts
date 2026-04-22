const TRUNCATION_THRESHOLD_LINES = 3000;
const TRUNCATION_WINDOW_LINES = 100;

export interface RenderOptions {
    focusLine?: number;
}

export function renderWithLineNumbers(content: string, options: RenderOptions = {}): string {
    const lines = splitLines(content);

    if (lines.length <= TRUNCATION_THRESHOLD_LINES) {
        return renderRange(lines, 1, lines.length);
    }

    const focus = clamp(options.focusLine ?? 1, 1, lines.length);
    const start = Math.max(1, focus - TRUNCATION_WINDOW_LINES);
    const end = Math.min(lines.length, focus + TRUNCATION_WINDOW_LINES);

    const header = `[truncated — showing lines ${start}..${end} of ${lines.length}]`;
    return `${header}\n${renderRange(lines, start, end)}`;
}

function renderRange(lines: string[], startLine: number, endLine: number): string {
    const gutterWidth = String(endLine).length;
    const out: string[] = [];
    for (let lineNumber = startLine; lineNumber <= endLine; lineNumber++) {
        const prefix = String(lineNumber).padStart(gutterWidth, ' ');
        out.push(`${prefix} | ${lines[lineNumber - 1]}`);
    }
    return out.join('\n');
}

function splitLines(content: string): string[] {
    return content.split(/\r?\n/);
}

function clamp(value: number, min: number, max: number): number {
    if (value < min) return min;
    if (value > max) return max;
    return value;
}
