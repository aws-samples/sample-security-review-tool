import { BeforeToolCallEvent, LocalAgent, Plugin } from '@strands-agents/sdk';

/**
 * Caps the number of times `apply_fix` can be called in a single session.
 *
 * When the limit is exceeded, sets `event.cancel` with an instruction for the
 * model to call `give_up` instead of a hard session termination. This keeps
 * the agent loop's normal stopReason machinery intact (gave_up vs. cancelled).
 */
export class ApplyFixLimitPlugin implements Plugin {
    readonly name = 'srt:apply-fix-limit';

    private count = 0;

    constructor(private readonly maxApplyFixCalls: number) {}

    initAgent(agent: LocalAgent): void {
        agent.addHook(BeforeToolCallEvent, (event) => {
            if (event.toolUse.name !== 'apply_fix') return;
            this.count += 1;
            if (this.count > this.maxApplyFixCalls) {
                event.cancel =
                    `apply_fix has already been attempted ${this.maxApplyFixCalls} times without success. ` +
                    `Stop calling apply_fix and call give_up instead with a one-sentence reason.`;
            }
        });
    }
}
