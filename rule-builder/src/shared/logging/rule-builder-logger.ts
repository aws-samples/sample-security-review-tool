import { BannerTheme, type Theme } from './theme.js';

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

    // Frames an agent.invoke() call: begin rule, the agent's live stream, then a footer rule with elapsed + outcome.
    public async agentBlock<T>(title: string, run: () => Promise<T>): Promise<T> {
        const startedAt = performance.now();
        this.write(this.theme.agentBegin(title));
        try {
            const result = await run();
            this.write(this.theme.agentEnd(true, this.elapsedSince(startedAt)));
            return result;
        } catch (error) {
            this.write(this.theme.agentEnd(false, this.elapsedSince(startedAt)));
            throw error;
        }
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

    public error(message: string): void {
        this.write(this.theme.error(message));
    }

    private elapsedSince(startedAt: number): number {
        return performance.now() - startedAt;
    }

    private write(line: string): void {
        console.log(line);
    }
}
