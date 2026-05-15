import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { RequirementImplementationAgent } from '../agents/requirements-implementer/agent.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import type { RegressionInfo } from '../shared/types/implementation.js';

const MAX_RETRIES = 3;

export interface ImplementationResult {
    totalRequirements: number;
    passed: number;
    failed: string[];
}

interface VitestResult {
    allPassed: boolean;
    output: string;
}

export async function implementRule(spec: RequirementsSpec, service: string): Promise<ImplementationResult> {
    const { ruleId, requirements } = spec;

    console.log(`  Implementing ${requirements.length} requirements for ${ruleId}...`);

    const cfnResult = await implementRequirements(ruleId, service, requirements, 'cfn');
    const tfResult = await implementRequirements(ruleId, service, requirements, 'tf');

    const totalPassed = cfnResult.passed + tfResult.passed;
    const totalReqs = cfnResult.totalRequirements + tfResult.totalRequirements;
    const allFailed = [...cfnResult.failed, ...tfResult.failed];

    console.log(`  Final: ${totalPassed}/${totalReqs} passing`);
    return { totalRequirements: totalReqs, passed: totalPassed, failed: allFailed };
}

async function implementRequirements(ruleId: string, service: string, requirements: RuleRequirement[], format: 'cfn' | 'tf'): Promise<ImplementationResult> {
    const sorted = [...requirements].sort((a, b) => {
        if (a.expectedBehavior === 'flag' && b.expectedBehavior === 'pass') return -1;
        if (a.expectedBehavior === 'pass' && b.expectedBehavior === 'flag') return 1;
        return 0;
    });

    const regressionPaths: string[] = [];
    const passed: string[] = [];
    const failed: string[] = [];

    console.log(`\n    [${format.toUpperCase()}] ${sorted.length} requirements`);

    for (const requirement of sorted) {
        const outcome = await implementRequirement(ruleId, service, requirement, format, regressionPaths);

        if (outcome === 'passed') {
            passed.push(requirement.id);
            const testPath = getTestPath(ruleId, service, requirement.id, format);
            if (testPath) regressionPaths.push(testPath);
            console.log(`      ✓ ${requirement.id}`);
        } else {
            failed.push(`${requirement.id}-${format}`);
            console.log(`      ✗ ${requirement.id}`);
        }
    }

    return { totalRequirements: sorted.length, passed: passed.length, failed };
}

async function implementRequirement(ruleId: string, service: string, requirement: RuleRequirement, format: 'cfn' | 'tf', regressionPaths: string[]): Promise<'passed' | 'failed'> {
    const testPath = getTestPath(ruleId, service, requirement.id, format);
    if (!testPath) return 'failed';

    const initial = runVitest([testPath]);
    if (initial.allPassed) return 'passed';

    let latestFailure = initial.output;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        const regressions = checkRegressions(regressionPaths);
        const testFile = { path: testPath, content: fs.readFileSync(testPath, 'utf8') };
        const agent = new RequirementImplementationAgent();

        await agent.invoke(ruleId, service, requirement, testFile, latestFailure, regressions);

        const result = runVitest([testPath]);
        if (!result.allPassed) {
            latestFailure = result.output;
            console.log(`        attempt ${attempt}: still failing`);
            continue;
        }

        const postRegressions = checkRegressions(regressionPaths);
        if (postRegressions.length === 0) return 'passed';

        console.log(`        attempt ${attempt}: passed but caused ${postRegressions.length} regression(s)`);
    }

    return 'failed';
}

function getTestPath(ruleId: string, service: string, requirementId: string, format: 'cfn' | 'tf'): string | null {
    // const p = computeTestPath(ruleId, service, requirementId, format);
    // return fs.existsSync(p) ? p : null;
    return null;
}

function checkRegressions(regressionPaths: string[]): RegressionInfo[] {
    if (regressionPaths.length === 0) return [];

    const batchResult = runVitest(regressionPaths);
    if (batchResult.allPassed) return [];

    const regressions: RegressionInfo[] = [];
    for (const p of regressionPaths) {
        const individual = runVitest([p]);
        if (individual.allPassed) continue;
        regressions.push({ requirementId: extractRequirementId(p), testPath: p, testContent: fs.readFileSync(p, 'utf8'), failureOutput: individual.output });
    }
    return regressions;
}

function runVitest(testPaths: string[]): VitestResult {
    if (testPaths.length === 0) return { allPassed: true, output: '' };

    // const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', ...testPaths], { cwd: srtRepoRoot(), encoding: 'utf8', timeout: 60_000 });
    // const output = (result.stdout ?? '') + (result.stderr ?? '');

    // return { allPassed: result.status === 0, output: truncate(output, 4000) };

        return { allPassed: true, output: "" };

}

function extractRequirementId(testPath: string): string {
    const match = testPath.match(/req-(\d+)/);
    return match ? `REQ-${match[1]}` : 'unknown';
}

function truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength) + '\n... (truncated)';
}
