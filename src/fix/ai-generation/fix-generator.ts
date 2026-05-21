import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { StrandsFixAgent } from '../agent/fix-agent.js';
import { Fix } from '../types.js';

export class FixGenerator {
    constructor(private readonly context: ProjectContext) {}

    public async generateFix(issue: ScanResult): Promise<Fix | null> {
        try {
            if (!issue.path || !issue.issue || !issue.fix) {
                return null;
            }

            return await this.generateFixWithAgent(issue);
        } catch (error) {
            SrtLogger.logError('Fix generation failed', error as Error, { checkId: issue.check_id, path: issue.path });
            return null;
        }
    }

    private async generateFixWithAgent(issue: ScanResult): Promise<Fix | null> {
        const agent = new StrandsFixAgent(this.context);
        const result = await agent.run(issue);

        if (result.stopReason !== 'finished') {
            SrtLogger.logError(
                `StrandsFixAgent did not complete cleanly (stopReason: ${result.stopReason})`,
                new Error(`Edits: ${result.edits.length}${result.gaveUpReason ? `, gave up: ${result.gaveUpReason}` : ''}`),
                { checkId: issue.check_id, path: issue.path },
            );
        }
        
        return agent.toFix(result);
    }
}
