import type { Plugin, LocalAgent, BeforeToolCallEvent as BeforeToolCallEventType } from '@strands-agents/sdk';
import { BeforeToolCallEvent } from '@strands-agents/sdk';

const EVALUATOR_TOOLS = new Set(['scan_fixture', 'run_fix', 'rescan_fixture']);

export class IterationLimitPlugin implements Plugin {
    readonly name = 'refiner:iteration-limit';
    private totalToolCalls = 0;
    private evalToolCalls = 0;

    constructor(
        private readonly maxTotalToolCalls: number = 200,
        private readonly maxEvalToolCalls: number = 20,
    ) {}

    initAgent(agent: LocalAgent): void {
        agent.addHook(BeforeToolCallEvent, (event: BeforeToolCallEventType) => {
            this.totalToolCalls++;
            if (this.totalToolCalls > this.maxTotalToolCalls) {
                event.cancel = `Maximum total tool calls (${this.maxTotalToolCalls}) reached. Call submit_result now.`;
                return;
            }
            if (EVALUATOR_TOOLS.has(event.toolUse.name)) {
                this.evalToolCalls++;
                if (this.evalToolCalls > this.maxEvalToolCalls) {
                    event.cancel = `Maximum evaluator tool calls (${this.maxEvalToolCalls}) reached. Call submit_result now.`;
                }
            }
        });
    }
}
