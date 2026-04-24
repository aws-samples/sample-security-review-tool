import { execSync } from 'node:child_process';
import * as path from 'node:path';
import { tool, JSONValue } from '@strands-agents/sdk';
import z from 'zod';
import type { RefinerSession } from '../types.js';

export function createResetFixtureTool(session: RefinerSession) {
    return tool({
        name: 'reset_fixture',
        description: 'Reset a fixture directory to its baseline git commit. Only works on fixture directories.',
        inputSchema: z.object({
            fixtureDir: z.string().min(1).describe('Absolute path to the fixture directory.'),
        }),
        callback: async (input): Promise<JSONValue> => {
            const resolved = path.resolve(input.fixtureDir);
            if (!resolved.startsWith(session.fixturesRoot)) {
                return { error: `Path must be under ${session.fixturesRoot}` };
            }
            execSync('git reset --hard -q HEAD', { cwd: resolved, stdio: 'ignore' });
            execSync('git clean -fdxq', { cwd: resolved, stdio: 'ignore' });
            return { reset: true };
        },
    });
}
