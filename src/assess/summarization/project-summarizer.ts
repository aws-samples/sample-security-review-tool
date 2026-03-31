import * as path from 'path';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { writeTextFile, ensureDirectoryExists } from '../../shared/file-system/file-utils.js';
import * as bedrockUtils from '../../shared/ai/bedrock-client.js';
import { ContextCollector } from './context-collector.js';
import { PROJECT_SUMMARY_PROMPT } from './project-summary-prompt.js';
import { TemplateResult } from '../types.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class ProjectSummarizer {
    private readonly contextCollector = new ContextCollector();

    constructor(private readonly context: ProjectContext, private readonly onProgress: (progress: string) => void = () => { }) {  }

    public async summarize(templateResults: TemplateResult[]): Promise<string | null> {
        try {
            this.onProgress('  › Collecting project context...');
            const context = await this.contextCollector.collect(this.context.getProjectRootFolderPath(), templateResults);
            this.onProgress('  ✔ Collected project context');

            if (!context.trim())  return null;

            this.onProgress('  › Creating project summary...');
            const summary = await bedrockUtils.sendPrompt(PROJECT_SUMMARY_PROMPT, context);
            this.onProgress('  ✔ Created project summary');

            if (!summary?.trim()) return null;

            const cleanedSummary = summary.trim();

            this.onProgress('  › Saving project summary...');
            await this.saveSummary(cleanedSummary);
            this.onProgress('  ✔ Saved project summary');

            return cleanedSummary;
        } catch (error) {
            this.onProgress('  ✗ Failed to generate project summary');
            SrtLogger.logError('Error generating project summary', error as Error);
            return null;
        }
    }

    private async saveSummary(summary: string): Promise<void> {
        await ensureDirectoryExists(this.context.getSrtOutputFolderPath());
        const filePath = path.join(this.context.getSrtOutputFolderPath(), 'project-summary.md');
        await writeTextFile(filePath, summary);
    }
}
