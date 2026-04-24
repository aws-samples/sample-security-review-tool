import * as fs from 'node:fs';
import * as path from 'node:path';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import type { RefinerSession } from '../types.js';

const MAX_BYTES = 50 * 1024;

export function createReadFileTool(session: RefinerSession) {
    return tool({
        name: 'read_file',
        description: 'Read a file with line numbers. Path must be under the SRT repo root or fixtures root.',
        inputSchema: z.object({
            path: z.string().min(1).describe('Absolute path to the file to read.'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.path);
            if (!resolved.startsWith(session.srtRepoRoot) && !resolved.startsWith(session.fixturesRoot)) {
                return { error: `Path must be under ${session.srtRepoRoot} or ${session.fixturesRoot}` };
            }
            if (!fs.existsSync(resolved)) {
                return { error: `File not found: ${resolved}` };
            }
            const stat = fs.statSync(resolved);
            if (!stat.isFile()) {
                return { error: `Not a file: ${resolved}` };
            }
            let content = fs.readFileSync(resolved, 'utf8');
            if (content.length > MAX_BYTES) {
                content = content.slice(0, MAX_BYTES) + '\n... (truncated)';
            }
            const numbered = content
                .split('\n')
                .map((line, i) => `${i + 1}\t${line}`)
                .join('\n');
            return { path: resolved, content: numbered };
        },
    });
}
