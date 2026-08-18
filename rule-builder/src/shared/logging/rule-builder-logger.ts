import { BannerTheme, type Theme } from './theme.js';
import { SrtLogger } from '../../../../src/shared/logging/srt-logger.js';
import { formatErrorSummary } from '../../../../src/shared/error-handling/error-diagnostics.js';

// Semantic logging API for the rule-builder workflow. Call sites speak intent ("phaseStart", "success");
// the Theme owns every glyph, color, and rule. Swap the look by passing a different Theme — nothing else changes.
export class RuleBuilderLogger {
    private runStartedAt = 0;
    private phaseStartedAt = 0;

    constructor(private readonly theme: Theme = new BannerTheme()) {}

    public runStart(ruleId: string, description: string): void {
        this.runStartedAt = performance.now();
        this.write(this.theme.runStart(ruleId, description));
    }

    public runComplete(ruleId: string): void {
        this.write(this.theme.runComplete(ruleId, this.elapsedSince(this.runStartedAt)));
    }

    public phaseStart(number: number, total: number, title: string): void {
        this.phaseStartedAt = performance.now();
        this.write(this.theme.phaseStart(number, total, title));
    }

    public phaseComplete(summary: string): void {
        this.write(this.theme.phaseComplete(summary, this.elapsedSince(this.phaseStartedAt)));
    }

    public async task<T>(label: string, run: () => Promise<T>): Promise<T> {
        const startedAt = performance.now();
        this.itemStart(label);
        try {
            const result = await run();
            this.itemEnd(true, 'done', this.elapsedSince(startedAt));
            return result;
        } catch (error) {
            this.itemEnd(false, 'failed', this.elapsedSince(startedAt));
            throw error;
        }
    }

    // task() parks the cursor on an open line, which overlapping calls would trample.
    public async concurrentTask<T>(label: string, run: () => Promise<T>): Promise<T> {
        const startedAt = performance.now();
        try {
            const result = await run();
            this.writeItemLine(label, true, 'done', this.elapsedSince(startedAt));
            return result;
        } catch (error) {
            this.writeItemLine(label, false, 'failed', this.elapsedSince(startedAt));
            throw error;
        }
    }

    public group(label: string): void {
        this.write(this.theme.group(label));
    }

    // itemStart/itemContinue leave the line open — only itemEnd may write next.
    public itemStart(name: string): void {
        this.writeInline(this.theme.itemPending(name));
    }

    public itemContinue(): void {
        this.writeInline(this.theme.itemContinuation());
    }

    public itemEnd(succeeded: boolean, status: string, elapsedMs?: number): void {
        this.write(this.theme.itemOutcome(succeeded, status, elapsedMs));
    }

    public step(message: string): void {
        this.write(this.theme.step(message));
    }

    public substep(message: string): void {
        this.write(this.theme.substep(message));
    }

    public success(message: string): void {
        this.write(this.theme.success(message));
    }

    public failure(message: string): void {
        this.write(this.theme.failure(message));
    }

    public warning(message: string): void {
        this.write(this.theme.warning(message));
    }

    public info(message: string): void {
        this.write(this.theme.info(message));
    }

    public error(error: unknown, logMessage = 'Rule builder failed'): void {
        this.write(this.theme.error(formatErrorSummary(error)));
        SrtLogger.logError(logMessage, error);
    }

    private elapsedSince(startedAt: number): number {
        return performance.now() - startedAt;
    }

    private writeItemLine(label: string, succeeded: boolean, status: string, elapsedMs: number): void {
        this.write(this.theme.itemPending(label) + this.theme.itemOutcome(succeeded, status, elapsedMs));
    }

    private write(line: string): void {
        console.log(line);
    }

    private writeInline(text: string): void {
        process.stdout.write(text);
    }
}
