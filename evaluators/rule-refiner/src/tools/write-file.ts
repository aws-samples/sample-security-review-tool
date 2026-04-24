import * as fs from 'node:fs';
import * as path from 'node:path';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import type { RefinerSession } from '../types.js';

const RULES_DIR_SEGMENT = path.join('src', 'assess', 'scanning', 'security-matrix', 'rules');

export function createWriteFileTool(session: RefinerSession) {
    return tool({
        name: 'write_file',
        description: 'Write the complete contents of a file. For rule source edits the path must be a .ts file under the security-matrix rules directory. For fixture files use write_fixture_files instead.',
        inputSchema: z.object({
            path: z.string().min(1).describe('Absolute path to the file to write.'),
            content: z.string().describe('The complete new file contents.'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.path);
            const isRuleSource = resolved.includes(RULES_DIR_SEGMENT);
            const isFixture = resolved.startsWith(session.fixturesRoot);

            if (!isRuleSource && !isFixture) {
                return { error: `write_file only allows editing rule source files (under rules/) or fixture files. Got: ${resolved}` };
            }
            if (isRuleSource && !resolved.endsWith('.ts')) {
                return { error: 'Rule source files must end in .ts' };
            }
            if (isRuleSource && session.originalRuleSource === null && fs.existsSync(resolved)) {
                session.originalRuleSource = fs.readFileSync(resolved, 'utf8');
            }

            fs.mkdirSync(path.dirname(resolved), { recursive: true });
            fs.writeFileSync(resolved, input.content, 'utf8');
            return { written: true, path: resolved, bytesWritten: Buffer.byteLength(input.content, 'utf8') };
        },
    });
}
