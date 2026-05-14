import * as fs from 'node:fs';
import * as path from 'node:path';
import { srtRepoRoot } from '../shared/fixture-paths.js';
import { ScaffolderAgent } from '../agents/scaffolder/agent.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';

export async function scaffold(ruleId: string, service: string, description: string, spec: RequirementsSpec): Promise<void> {
    const rulesDir = path.join(srtRepoRoot(), 'src', 'assess', 'scanning', 'security-matrix', 'rules', service);
    const controlPath = path.join(rulesDir, 'controls', `${ruleId.toLowerCase()}.control.ts`);
    const adaptersDir = path.join(rulesDir, 'adapters');

    if (fs.existsSync(controlPath)) {
        console.log('  Scaffold skipped — control already exists.');
        return;
    }

    const adaptersExist = fs.existsSync(adaptersDir) && fs.readdirSync(adaptersDir).some(f => f.endsWith('-adapter.ts'));

    fs.mkdirSync(path.dirname(controlPath), { recursive: true });
    if (!adaptersExist) {
        fs.mkdirSync(adaptersDir, { recursive: true });
    }

    const agent = new ScaffolderAgent();
    await agent.invoke(ruleId, service, description, spec, controlPath, adaptersDir, adaptersExist);

    ensureControlsIndex(rulesDir, ruleId, controlPath);
    console.log(`  Scaffold created: ${controlPath}`);
}

function ensureControlsIndex(rulesDir: string, ruleId: string, controlPath: string): void {
    const indexPath = path.join(rulesDir, 'controls', 'index.ts');
    const controlFileName = path.basename(controlPath, '.ts');
    const instanceName = toCamelCaseInstance(ruleId);
    const exportLine = `export { ${instanceName}Control } from './${controlFileName}.js';\n`;

    if (fs.existsSync(indexPath)) {
        const content = fs.readFileSync(indexPath, 'utf8');
        if (content.includes(instanceName)) return;
        fs.appendFileSync(indexPath, exportLine);
    } else {
        fs.writeFileSync(indexPath, exportLine);
    }
}

function toCamelCaseInstance(ruleId: string): string {
    const parts = ruleId.toLowerCase().split('-');
    return parts[0] + parts.slice(1).map(p => p.charAt(0).toUpperCase() + p.slice(1)).join('');
}
