import * as path from 'node:path';
import * as url from 'node:url';
import { Evaluator } from './evaluator.js';

async function main(): Promise<void> {
    const targetProjectPath = process.argv[2];
    if (!targetProjectPath) {
        console.error('Usage: bun src/index.ts <target-project-path>');
        process.exit(1);
    }

    const moduleDir = path.dirname(url.fileURLToPath(import.meta.url));
    const srtRepoRoot = path.resolve(moduleDir, '..', '..');
    const reportsDir = path.resolve(moduleDir, '..', 'reports');

    const evaluator = new Evaluator(
        path.resolve(targetProjectPath),
        srtRepoRoot,
        reportsDir,
    );

    const { markdownPath, jsonPath } = await evaluator.evaluate();
    console.log(`\nReports written:`);
    console.log(`  ${markdownPath}`);
    console.log(`  ${jsonPath}`);
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
