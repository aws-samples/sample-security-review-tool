import { TestGeneratorAgent } from '../agents/test-generator/agent.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';

const MAX_CONCURRENCY = 4;

interface TestTask {
    requirementId: string;
    format: 'cfn' | 'tf';
}

export async function generateTests(ruleId: string, service: string, spec: RequirementsSpec): Promise<void> {
    const tasks: TestTask[] = spec.requirements.flatMap(r => [
        { requirementId: r.id, format: 'cfn' as const },
        { requirementId: r.id, format: 'tf' as const },
    ]);

    console.log(`  Generating ${tasks.length} test files (${MAX_CONCURRENCY} at a time)...`);

    let successes = 0;
    let failures = 0;

    for (let i = 0; i < tasks.length; i += MAX_CONCURRENCY) {
        const batch = tasks.slice(i, i + MAX_CONCURRENCY);

        const results = await Promise.allSettled(batch.map(async (task) => {
            const requirement = spec.requirements.find(r => r.id === task.requirementId)!;
            const agent = new TestGeneratorAgent();
            await agent.invoke(requirement, ruleId, service, task.format);
            console.log(`    ✓ ${task.requirementId} ${task.format}`);
        }));

        for (const result of results) {
            if (result.status === 'fulfilled') {
                successes++;
            } else {
                failures++;
                const task = batch[results.indexOf(result)];
                console.log(`    ✗ ${task.requirementId} ${task.format}: ${result.reason?.message ?? result.reason}`);
            }
        }
    }

    console.log(`  Generated ${tasks.length} test files (${successes} successes, ${failures} failures)`);
}
