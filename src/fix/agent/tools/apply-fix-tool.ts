import * as path from 'path';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { FixValidator } from '../validation/fix-validator.js';
import { AgentSession } from '../types.js';
import { EditInput } from '../staging/edit-session.js';
import { renderWithLineNumbers } from '../prompts/line-numbered-source.js';
import { StrategyResult } from '../validation/types.js';

const editSchema = z.object({
    path: z.string().min(1).describe('Project-relative path using forward slashes.'),
    lineRange: z.tuple([z.number().int(), z.number().int()])
        .describe('Inclusive 1-based [start, end] line range. Use [n, n-1] to insert before line n. Use [1, 0] with a non-existent path to create a new file.'),
    newContent: z.string().describe('The replacement text. No diff markers (+, -, @@). Just the literal lines to write.'),
});

const applyFixSchema = z.object({
    edits: z.array(editSchema).min(1).describe('The complete set of edits for this fix. Every call is independent — include every edit you want in the final fix.'),
    explanation: z.string().min(1).describe('One or two sentences describing what the fix does and why it resolves the finding.'),
});

const APPLY_FIX_DESCRIPTION = [
    'Submit a complete fix. Validates automatically (cdk synth / cfn parse / tsc / node --check / py_compile).',
    'Every call is independent — the edits from any previous call are discarded before yours are applied.',
    'Line numbers in lineRange are always relative to the ORIGINAL file shown in the user message, not to a prior attempt.',
    'On success returns { valid: true, explanation }. On failure returns { valid: false, errors, originalFiles } so you can plan a new complete attempt.',
].join(' ');

export function createApplyFixTool(session: AgentSession, context: ProjectContext) {
    return tool({
        name: 'apply_fix',
        description: APPLY_FIX_DESCRIPTION,
        inputSchema: applyFixSchema,
        callback: async (input): Promise<JSONValue> => {
            const edits: EditInput[] = input.edits.map(edit => ({
                path: edit.path,
                lineRange: [edit.lineRange[0], edit.lineRange[1]],
                newContent: edit.newContent,
            }));

            const applied = await session.editSession.applyEdits(edits);
            if (!applied.ok) {
                session.editSession.reset();
                const response: { [key: string]: JSONValue } = {
                    applied: false,
                    reason: applied.reason,
                };
                if (applied.path) response.path = applied.path;
                return response;
            }

            const validator = new FixValidator(context, session.editSession.recorder);
            const validation = await validator.validate();
            session.lastValidation = validation;

            if (validation.isValid) {
                session.comments = input.explanation;
                session.finished = true;
                return { valid: true, explanation: input.explanation };
            }

            const errors = validation.checks
                .filter(check => !check.isValid)
                .map(formatStrategyError);

            const originalFiles = buildOriginalFilesResponse(session, context.getProjectRootFolderPath());
            session.editSession.reset();

            return { valid: false, errors, originalFiles };
        },
    });
}

function formatStrategyError(check: StrategyResult): { [key: string]: JSONValue } {
    return {
        strategy: check.strategy,
        output: (check.output ?? 'Validation failed without output.').trim(),
    };
}

function buildOriginalFilesResponse(
    session: AgentSession,
    projectRootFolderPath: string,
): JSONValue[] {
    const recorder = session.editSession.recorder;
    const response: JSONValue[] = [];
    for (const change of recorder.toFixChanges()) {
        const relative = toRelativePosix(change.filePath, projectRootFolderPath);
        const original = recorder.getOriginalContent(change.filePath) ?? '';
        const focusLine = findFocusLineFor(session, change.filePath);
        response.push({
            path: relative,
            content: renderWithLineNumbers(original, { focusLine }),
        });
    }
    return response;
}

function findFocusLineFor(session: AgentSession, absoluteFilePath: string): number | undefined {
    for (const source of session.loadedContext.sources) {
        if (path.resolve(source.path) === path.resolve(absoluteFilePath)) {
            return source.focusLine;
        }
    }
    return undefined;
}

function toRelativePosix(absolutePath: string, rootFolderPath: string): string {
    const relative = path.relative(rootFolderPath, absolutePath);
    return path.sep === '/' ? relative : relative.split(path.sep).join('/');
}
