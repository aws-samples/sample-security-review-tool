import * as fs from 'node:fs';
import { RuleScaffolder } from '../agents/scaffolder/index.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import { RuleContext } from '../shared/rule-context.js';

export async function scaffold(context: RuleContext, spec: RequirementsSpec): Promise<void> {
    if (fs.existsSync(context.ruleControlFilePath)) {
        console.log('  Scaffold skipped — control already exists.');
        return;
    }

    new RuleScaffolder().scaffold(context, spec);
    console.log(`Scaffold created: ${context.ruleControlFilePath}`);
}