import * as fs from 'node:fs';
import * as path from 'node:path';
import { tool, type JSONValue } from '@strands-agents/sdk';
import z from 'zod';

const MAX_BYTES = 50 * 1024;

export function createReadFileTool(rulesDir: string) {
    return tool({
        name: 'read_file',
        description: 'Read a file under the security-matrix rules directory.',
        inputSchema: z.object({
            path: z.string().min(1).describe('Absolute path to the file to read.'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.path);
            if (!resolved.startsWith(rulesDir)) {
                return { error: `Path must be under ${rulesDir}` };
            }
            if (!fs.existsSync(resolved)) {
                return { error: `File not found: ${resolved}` };
            }
            let content = fs.readFileSync(resolved, 'utf8');
            if (content.length > MAX_BYTES) {
                content = content.slice(0, MAX_BYTES) + '\n... (truncated)';
            }
            const numbered = content.split('\n').map((line, i) => `${i + 1}\t${line}`).join('\n');
            return { path: resolved, content: numbered };
        },
    });
}

export function createWriteFileTool(rulesDir: string) {
    return tool({
        name: 'write_file',
        description: 'Write the complete contents of a rule source file. Path must be a .ts file under the rules directory.',
        inputSchema: z.object({
            path: z.string().min(1).describe('Absolute path to the file to write.'),
            content: z.string().describe('The complete new file contents.'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.path);
            if (!resolved.startsWith(rulesDir)) {
                return { error: `Path must be under ${rulesDir}` };
            }
            if (!resolved.endsWith('.ts')) {
                return { error: 'Rule source files must end in .ts' };
            }
            fs.writeFileSync(resolved, input.content, 'utf8');
            return { written: true, path: resolved, bytesWritten: Buffer.byteLength(input.content, 'utf8') };
        },
    });
}
