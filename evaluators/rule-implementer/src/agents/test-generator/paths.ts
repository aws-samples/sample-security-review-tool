import * as fs from 'node:fs';
import * as path from 'node:path';
import { srtRepoRoot } from '../../shared/fixture-paths.js';

export interface TestPaths {
    testPath: string;
    controlPath: string;
    cfnFactoryPath: string | null;
    tfFactoryPath: string | null;
}

export function computeTestPath(ruleId: string, service: string, requirementId: string, format: 'cfn' | 'tf'): string {
    const nn = requirementId.replace(/\D/g, '').padStart(2, '0');
    const ruleIdLower = ruleId.toLowerCase();
    return path.join(srtRepoRoot(), 'tests', 'core', 'scanners', 'srt', 'rules', service, ruleIdLower, `req-${nn}.${format}.tests.ts`);
}

export function computeControlPath(ruleId: string, service: string): string {
    return path.join(srtRepoRoot(), 'src', 'assess', 'scanning', 'security-matrix', 'rules', service, 'controls', `${ruleId.toLowerCase()}.control.ts`);
}

export function computeAdapterFactoryPath(service: string, format: 'cfn' | 'tf'): string | null {
    const adaptersDir = path.join(srtRepoRoot(), 'src', 'assess', 'scanning', 'security-matrix', 'rules', service, 'adapters');
    if (!fs.existsSync(adaptersDir)) return null;

    const prefix = format === 'cfn' ? 'cfn-' : 'tf-';
    const files = fs.readdirSync(adaptersDir);
    const match = files.find(f => f.startsWith(prefix) && f.endsWith('-adapter.ts'));
    return match ? path.join(adaptersDir, match) : null;
}

export function resolveTestPaths(ruleId: string, service: string, requirementId: string, format: 'cfn' | 'tf'): TestPaths {
    return {
        testPath: computeTestPath(ruleId, service, requirementId, format),
        controlPath: computeControlPath(ruleId, service),
        cfnFactoryPath: computeAdapterFactoryPath(service, 'cfn'),
        tfFactoryPath: computeAdapterFactoryPath(service, 'tf'),
    };
}
