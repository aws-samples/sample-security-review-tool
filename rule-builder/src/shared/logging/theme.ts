// ─────────────────────────────────────────────────────────────────────────────
// CHANGING THE LOOK OF THE RULE-BUILDER LOGS
//
// All visual styling lives in this file. The workflow code only ever calls the
// semantic methods on RuleBuilderLogger (phaseStart, task, success, ...),
// so changing the entire look means writing a new `Theme` here — nothing else.
//
// The active look is "BannerTheme" (bold `━━ 1/5  REQUIREMENTS ━━` phase rules,
// one line per agent call with leader dots, trailing dim durations).
//
// Two alternative looks were considered and can be added as drop-in themes:
//
//   • Clack gutter — a continuous left gutter (│) opened by ┌ and closed by └,
//     with ◇ ◆ ● ▲ ■ glyphs marking state. Calm/modern (the create-astro look).
//   • Build-tool — no gutter; a single ✓/✗ gates each line, dim leader dots
//     align trailing durations, hierarchy via indentation (the Vite/Bun look).
//
// To switch:
//   1. Add a new class here, e.g. `export class ClackGutterTheme implements Theme`,
//      implementing every method below (return fully-formatted strings).
//   2. In rule-builder-logger.ts, change the default theme in the constructor:
//      `constructor(private readonly theme: Theme = new ClackGutterTheme())`.
//   That's the only change — no call site is touched.
//
// (Just ask Claude to "switch the rule-builder logs to the Clack gutter theme"
//  and it can do steps 1–2 from this note.)
// ─────────────────────────────────────────────────────────────────────────────

import { Chalk, type ChalkInstance } from 'chalk';

const DEFAULT_WIDTH = 80;
const MILLIS_PER_SECOND = 1000;
const SECONDS_PER_MINUTE = 60;

// Detects what the output stream can render so the theme can downgrade gracefully.
export class TerminalCapabilities {
    constructor(private readonly stream: NodeJS.WriteStream = process.stdout, private readonly env: NodeJS.ProcessEnv = process.env) {}

    public get color(): boolean {
        if (this.env.FORCE_COLOR) return true;
        if (this.env.NO_COLOR) return false;
        if (this.env.TERM === 'dumb') return false;
        return this.stream.isTTY === true;
    }

    // Box-drawing glyphs are reserved for interactive terminals; piped/CI output stays ASCII and greppable.
    public get unicode(): boolean {
        return this.stream.isTTY === true;
    }

    public get width(): number {
        return this.stream.columns ?? DEFAULT_WIDTH;
    }
}

// A fully-formatted, ready-to-print line (or block) for one semantic logging event. Pure: no side effects.
export interface Theme {
    runStart(ruleId: string, description: string): string;
    runComplete(ruleId: string, elapsedMs: number): string;
    phaseStart(number: number, total: number, title: string): string;
    phaseComplete(summary: string, elapsedMs: number): string;
    group(label: string): string;
    itemPending(name: string): string;
    itemContinuation(): string;
    itemOutcome(succeeded: boolean, status: string, elapsedMs?: number): string;
    itemNote(message: string): string;
    step(message: string): string;
    substep(message: string): string;
    success(message: string): string;
    failure(message: string): string;
    warning(message: string): string;
    info(message: string): string;
    error(message: string): string;
}

interface Glyphs {
    success: string;
    failure: string;
    warning: string;
    info: string;
    arrow: string;
    separator: string;
    bannerRule: string;
}

const UNICODE_GLYPHS: Glyphs = { success: '✔', failure: '✗', warning: '!', info: '·', arrow: '›', separator: '·', bannerRule: '━' };
const ASCII_GLYPHS: Glyphs = { success: '*', failure: 'x', warning: '!', info: '-', arrow: '>', separator: '-', bannerRule: '=' };

const ITEM_INDENT = '    ';
const STATUS_COLUMN = 58;
const MIN_STATUS_COLUMN = 24;

// The "banner rules" aesthetic: bold phase rules, dot-led item lines, trailing dim durations.
export class BannerTheme implements Theme {
    private readonly chalk: ChalkInstance;
    private readonly glyphs: Glyphs;

    constructor(private readonly capabilities: TerminalCapabilities = new TerminalCapabilities()) {
        this.chalk = new Chalk({ level: capabilities.color ? 1 : 0 });
        this.glyphs = capabilities.unicode ? UNICODE_GLYPHS : ASCII_GLYPHS;
    }

    public runStart(ruleId: string, description: string): string {
        return `\n${this.chalk.bold(`rule-builder ${this.glyphs.separator} ${ruleId}`)}\n${this.chalk.dim(description)}\n`;
    }

    public runComplete(ruleId: string, elapsedMs: number): string {
        return `\n${this.chalk.green.bold(`${this.glyphs.success} Done in ${this.duration(elapsedMs)}`)} ${this.chalk.dim(`${this.glyphs.separator} ${ruleId} implemented`)}\n`;
    }

    public phaseStart(number: number, total: number, title: string): string {
        const label = `${number}/${total}  ${title.toUpperCase()}`;
        return `\n${this.chalk.bold.cyan(this.banner(label))}`;
    }

    public phaseComplete(summary: string, elapsedMs: number): string {
        return `  ${this.chalk.green(this.glyphs.success)} ${summary} ${this.chalk.dim(`${this.glyphs.separator} ${this.duration(elapsedMs)}`)}`;
    }

    public group(label: string): string {
        return `  ${this.chalk.bold(label)}`;
    }

    // Opens a line and parks the cursor at the status column; itemOutcome closes it. Nothing may print in between.
    public itemPending(name: string): string {
        const prefix = `${ITEM_INDENT}${name} `;
        const leader = this.glyphs.separator.repeat(Math.max(1, this.statusColumn() - this.visibleLength(prefix)));
        return `${prefix}${this.chalk.dim(leader)} `;
    }

    public itemContinuation(): string {
        return ' '.repeat(this.statusColumn() + 1);
    }

    public itemOutcome(succeeded: boolean, status: string, elapsedMs?: number): string {
        const glyph = succeeded ? this.chalk.green(this.glyphs.success) : this.chalk.red(this.glyphs.failure);
        const text = succeeded ? status : this.chalk.red(status);
        const elapsed = elapsedMs === undefined ? '' : this.chalk.dim(` ${this.glyphs.separator} ${this.duration(elapsedMs)}`);
        return `${glyph} ${text}${elapsed}`;
    }

    public itemNote(message: string): string {
        return `${ITEM_INDENT}  ${this.chalk.dim(message)}`;
    }

    public step(message: string): string {
        return `  ${this.chalk.dim(this.glyphs.arrow)} ${message}`;
    }

    public substep(message: string): string {
        return `    ${this.chalk.dim(this.glyphs.arrow)} ${message}`;
    }

    public success(message: string): string {
        return `  ${this.chalk.green(this.glyphs.success)} ${message}`;
    }

    public failure(message: string): string {
        return `  ${this.chalk.red(this.glyphs.failure)} ${message}`;
    }

    public warning(message: string): string {
        return `  ${this.chalk.yellow(this.glyphs.warning)} ${message}`;
    }

    public info(message: string): string {
        return `  ${this.chalk.blue(this.glyphs.info)} ${message}`;
    }

    public error(message: string): string {
        return `\n${this.chalk.red.bold(`${this.glyphs.failure} ${message}`)}\n`;
    }

    private banner(label: string): string {
        const rule = this.glyphs.bannerRule;
        const prefix = `${rule}${rule} ${label} `;
        return prefix + rule.repeat(Math.max(0, this.capabilities.width - this.visibleLength(prefix)));
    }

    private statusColumn(): number {
        return Math.max(MIN_STATUS_COLUMN, Math.min(STATUS_COLUMN, this.capabilities.width - MIN_STATUS_COLUMN));
    }

    private visibleLength(text: string): number {
        return text.replace(/\x1b\[[0-9;]*m/g, '').length;
    }

    private duration(elapsedMs: number): string {
        if (elapsedMs < MILLIS_PER_SECOND) return `${Math.round(elapsedMs)}ms`;

        const totalSeconds = elapsedMs / MILLIS_PER_SECOND;
        if (totalSeconds < SECONDS_PER_MINUTE) return `${totalSeconds.toFixed(1)}s`;

        const minutes = Math.floor(totalSeconds / SECONDS_PER_MINUTE);
        const seconds = Math.round(totalSeconds % SECONDS_PER_MINUTE);
        return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
    }
}
