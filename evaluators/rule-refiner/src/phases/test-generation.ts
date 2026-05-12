import * as fs from 'fs';
import * as path from 'path';
import { TestGeneratorAgent } from '../agents/test-generator/agent.js';
import { RuleCatalog } from '../shared/rule-catalog/index.js';
import { srtRepoRoot } from '../shared/fixture-paths.js';
import type { FixtureFormat } from '../shared/rule-catalog/index.js';
import type { RequirementsSpec } from '../types/requirements.js';
import type { GeneratedFixture } from '../agents/fixture-generator/types.js';

export async function generateTestFile(spec: RequirementsSpec, fixtures: Map<string, GeneratedFixture>): Promise<string> {
    const { ruleId, format } = spec;
    const rule = await RuleCatalog.find(ruleId, format);

    const ruleClassName = extractClassName(rule.sourceLocation);
    const ruleImportPath = buildImportPath(rule.sourceLocation, ruleId, format);

    console.log(`  Generating test file for ${ruleId}...`);

    const agent = new TestGeneratorAgent();
    const testContent = await agent.invoke(ruleId, ruleClassName, ruleImportPath, rule.applicableResourceTypes ?? [], spec.requirements, fixtures);

    const testFilePath = buildTestFilePath(rule.sourceLocation);
    fs.mkdirSync(path.dirname(testFilePath), { recursive: true });
    fs.writeFileSync(testFilePath, testContent);

    console.log(`  Written: ${testFilePath}`);
    return testFilePath;
}

function extractClassName(sourceLocation: string): string {
    const content = fs.readFileSync(sourceLocation, 'utf-8');
    const match = content.match(/export\s+default\s+new\s+(\w+)/);
    if (match) return match[1];

    const classMatch = content.match(/export\s+class\s+(\w+)/);
    if (classMatch) return classMatch[1];

    return 'Rule';
}

function buildImportPath(sourceLocation: string, ruleId: string, format: FixtureFormat): string {
    const repoRoot = srtRepoRoot();
    const relative = path.relative(repoRoot, sourceLocation);
    return relative.replace(/\.ts$/, '.js');
}

function buildTestFilePath(sourceLocation: string): string {
    const repoRoot = srtRepoRoot();
    const relative = path.relative(repoRoot, sourceLocation);
    const parts = relative.replace('src/assess/scanning/security-matrix/rules/', '').replace(/\.ts$/, '.test.ts');
    return path.join(repoRoot, 'tests', 'core', 'scanners', 'srt', 'rules', parts);
}
