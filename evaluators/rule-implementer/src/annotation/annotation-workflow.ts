import * as fs from 'fs/promises';
import * as path from 'path';
import { RuleCatalog } from '../shared/rule-catalog/index.js';
import type { FixtureFormat } from '../shared/types/rule-catalog.js';
import { AnnotationAgent } from './annotation-agent.js';

export class AnnotationWorkflow {
    public async annotate(ruleId: string, fixtureFormat: FixtureFormat): Promise<void> {
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);
        const sourcePath = path.resolve(rule.sourceLocation);
        const currentSource = await fs.readFile(sourcePath, 'utf-8');

        const evaluationDate = new Date().toISOString().split('T')[0];
        const jsdocComment = await new AnnotationAgent().invoke(currentSource, evaluationDate);

        const annotatedSource = this.insertJsdocComment(currentSource, jsdocComment);
        await fs.writeFile(sourcePath, annotatedSource, 'utf-8');
    }

    private insertJsdocComment(source: string, jsdocComment: string): string {
        const existingJsdocPattern = /\/\*\*[\s\S]*?\*\/\s*(?=export\s+class\s)/;
        const cleanedSource = source.replace(existingJsdocPattern, '');

        const classPattern = /(export\s+class\s)/;
        const match = cleanedSource.match(classPattern);

        if (!match || match.index === undefined) {
            return jsdocComment + '\n' + cleanedSource;
        }

        const before = cleanedSource.slice(0, match.index).trimEnd();
        const after = cleanedSource.slice(match.index);

        return before + '\n' + jsdocComment + '\n' + after;
    }
}
