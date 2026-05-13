import type { BaseRule } from '../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import type { BaseTerraformRule } from '../../../../../src/assess/scanning/security-matrix/terraform-rule-base.js';
import { RuleCatalog } from '../../shared/rule-catalog/index.js';
import type { FixtureFormat } from '../../shared/types/rule-catalog.js';

export async function loadCloudFormationRule(checkId: string): Promise<BaseRule> {
    const sourcePath = await resolveSourcePath(checkId, 'cfn');
    const module = await importFresh(sourcePath);
    return module.default as BaseRule;
}

export async function loadTerraformRule(checkId: string): Promise<BaseTerraformRule> {
    const sourcePath = await resolveSourcePath(checkId, 'terraform');
    const module = await importFresh(sourcePath);
    return module.default as BaseTerraformRule;
}

async function resolveSourcePath(checkId: string, format: FixtureFormat): Promise<string> {
    const rule = await RuleCatalog.find(checkId, format);
    return rule.sourceLocation;
}

async function importFresh(modulePath: string): Promise<any> {
    const cacheBuster = `?t=${Date.now()}`;
    return import(modulePath + cacheBuster);
}
