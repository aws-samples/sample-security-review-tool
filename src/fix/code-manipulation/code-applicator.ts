import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { NodeFileReader } from '../../shared/file-system/node-file-reader.js';
import { NodeFileWriter } from '../../shared/file-system/node-file-writer.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { IssueFileResolver } from '../issues/issue-file-resolver.js';
import { IssueUpdater } from '../issues/issue-updater.js';
import { IndentationHandler } from './indentation-handler.js';
import { YamlIndentationHandler } from './yaml-indentation-handler.js';
import { Fix, FixChange } from '../types.js';

export class CodeApplicator {
    private readonly fileReader = new NodeFileReader();
    private readonly fileWriter = new NodeFileWriter();
    private readonly indentationHandler = new IndentationHandler();
    private readonly yamlIndentationHandler = new YamlIndentationHandler();
    private readonly issueFileResolver: IssueFileResolver;

    constructor(private readonly context: ProjectContext, private readonly issueUpdater: IssueUpdater) {
        this.issueFileResolver = new IssueFileResolver(context);
    }

    public async applyFix(issue: ScanResult, fix: Fix): Promise<void> {
        try {
            const changesByFile = this.groupChangesByFile(fix.changes);

            for (const [filePath, changes] of changesByFile.entries()) {
                await this.applyChangesToFile(filePath, changes);
            }

            await this.issueUpdater.markAsFixed(issue);

        } catch (error) {
            SrtLogger.logError('Error applying fix', error as Error);
            throw error;
        }
    }

    private groupChangesByFile(changes: FixChange[]): Map<string, FixChange[]> {
        const grouped = new Map<string, FixChange[]>();
        for (const change of changes) {
            if (!grouped.has(change.filePath)) {
                grouped.set(change.filePath, []);
            }
            grouped.get(change.filePath)!.push(change);
        }
        return grouped;
    }

    private async applyChangesToFile(filePath: string, changes: FixChange[]): Promise<void> {
        let fileContent = await this.fileReader.readTextFile(filePath);

        // Handle new file creation
        if (fileContent === null) {
            if (changes.every(c => c.original === '')) {
                fileContent = '';
            } else {
                throw new Error(`Unable to read file: ${filePath}`);
            }
        }

        const isCloudFormationTemplate = await this.context.isCloudFormationTemplate(filePath);
        const isCdkProject = await this.context.isCdkProject();

        // Sort changes by line number descending (bottom-up) to preserve line numbers
        const sortedChanges = [...changes].sort((a, b) => b.startingLineNumber - a.startingLineNumber);

        let appliedCount = 0;
        for (const change of sortedChanges) {
            const contentBefore: string = fileContent;

            if (change.original === '') {
                // New content - append to file
                fileContent = fileContent + (fileContent ? '\n' : '') + change.updated;
                appliedCount++;
            } else if (isCloudFormationTemplate && !isCdkProject) {
                fileContent = this.yamlIndentationHandler.replaceCloudFormationResource(
                    fileContent,
                    change.original,
                    change.updated,
                    filePath
                );
                if (fileContent !== contentBefore) appliedCount++;
            } else {
                fileContent = this.indentationHandler.replaceWithIndentation(fileContent, change.original, change.updated);
                if (fileContent !== contentBefore) appliedCount++;
            }
        }

        if (appliedCount === 0) {
            throw new Error(`Fix failed: none of the ${sortedChanges.length} changes could be applied to ${filePath}. The original code snippets may not match the file content exactly.`);
        }

        if (appliedCount < sortedChanges.length) {
            SrtLogger.logError(`Partial fix applied`, new Error(`Only ${appliedCount} of ${sortedChanges.length} changes were applied to ${filePath}`));
        }

        const writeSuccess = await this.fileWriter.writeTextFile(filePath, fileContent);
        if (!writeSuccess) throw new Error(`Failed to write updated content to file: ${filePath}`);
    }
}
