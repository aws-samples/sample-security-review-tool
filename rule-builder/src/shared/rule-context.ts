import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';

export class RuleContext {
    private static cachedSrtRoot: string | undefined;
    
    readonly safeRuleId: string;
    readonly srtRootFolderPath: string;
    readonly requirementsFilePath: string;
    readonly testsFolderPath: string;
    readonly rootFixtureFolderPath: string;
    readonly cdkFixtureResourceFilePath: string;
    readonly cdkFixtureTemplateFolderPath: string;
    readonly cdkFixtureOutputFolderPath: string;
    readonly terraformFixtureOutputFolderPath: string;
    readonly terraformFixtureTemplateFolderPath: string;
    readonly terraformFixtureResourceFilePath: string;
    readonly cloudFormationFixtureOutputFolderPath: string;
    readonly cloudFormationFixtureTemplateFolderPath: string;
    readonly cloudFormationFixtureResourceFilePath: string;
    readonly ruleFolderPath: string;
    readonly ruleControlFilePath: string;
    readonly ruleAdapterBaseFilePath: string;
    readonly ruleAdapterCfnFilePath: string;
    readonly ruleAdapterTfFilePath: string;
    readonly securityControlBaseFilePath: string;
    readonly securityControlTypesFilePath: string;
    readonly serviceControlsIndexPath: string;
    readonly controlsRegistryPath: string;
    readonly ruleFixtureFilePath: string;

    constructor(readonly ruleId: string, readonly service: string, readonly description: string) {
        this.safeRuleId = this.getSafeRuleId();
        this.srtRootFolderPath = this.getSrtRootFolderPath();
        this.ruleFolderPath = this.getRuleFolderPath();
        this.requirementsFilePath = this.getRequirementsFilePath();
        this.testsFolderPath = this.getTestsFolderPath();
        this.rootFixtureFolderPath = this.getRootFixtureFolderPath();
        this.cdkFixtureResourceFilePath = this.getCdkFixtureResourceFilePath();
        this.cdkFixtureTemplateFolderPath = this.getCdkFixtureTemplateFolderPath();
        this.cdkFixtureOutputFolderPath = this.getCdkFixtureOutputFolderPath();
        this.terraformFixtureOutputFolderPath = this.getTerraformFixtureOutputFolderPath();
        this.terraformFixtureTemplateFolderPath = this.getTerraformFixtureTemplateFolderPath();
        this.terraformFixtureResourceFilePath = this.getTerraformFixtureResourceFilePath();
        this.cloudFormationFixtureOutputFolderPath = this.getCloudFormationFixtureOutputFolderPath();
        this.cloudFormationFixtureTemplateFolderPath = this.getCloudFormationFixtureTemplateFolderPath();
        this.cloudFormationFixtureResourceFilePath = this.getCloudFormationFixtureResourceFilePath();
        this.ruleControlFilePath = this.getRuleControlFilePath();
        this.ruleAdapterBaseFilePath = this.getRuleAdapterBaseFilePath();
        this.ruleAdapterCfnFilePath = this.getRuleAdapterCfnFilePath();
        this.ruleAdapterTfFilePath = this.getRuleAdapterTfFilePath();
        this.securityControlBaseFilePath = this.getSecurityControlBaseFilePath();
        this.securityControlTypesFilePath = this.getSecurityControlTypesFilePath();
        this.serviceControlsIndexPath = this.getServiceControlsIndexPath();
        this.controlsRegistryPath = this.getControlsRegistryPath();
        this.ruleFixtureFilePath = this.getRuleFixtureFilePath();
    }

    private getSrtRootFolderPath(): string {
        if (RuleContext.cachedSrtRoot) return RuleContext.cachedSrtRoot;

        let dir = path.dirname(url.fileURLToPath(import.meta.url));

        while (dir !== path.dirname(dir)) {
            try {
                const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8'));
                if (pkg.name === 'security-review-tool') { RuleContext.cachedSrtRoot = dir; return dir; }
            } catch { }

            dir = path.dirname(dir);
        }

        throw new Error('Could not find SRT root folder');
    }

    private getRequirementsFilePath(): string {
        return path.join(this.ruleFolderPath, `${this.safeRuleId}.requirements.json`);
    }

    private getTestsFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'tests', 'core', 'scanners', 'srt', 'rules', this.service, this.safeRuleId);
    }

    private getRootFixtureFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'rule-builder', 'src', 'remediation', 'fixtures', this.safeRuleId);
    }

    private getCdkFixtureOutputFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'fixtures', this.safeRuleId, 'cdk');
    }

    private getCdkFixtureTemplateFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'rule-builder', 'src', 'fixtures', 'templates', 'cdk');
    }

    private getCdkFixtureResourceFilePath(): string {
        return path.join(this.srtRootFolderPath, 'rule-builder', 'src', 'shared', 'rules', this.service, this.safeRuleId, `${this.safeRuleId}.ts`);
    }

    private getTerraformFixtureOutputFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'fixtures', this.safeRuleId, 'terraform');
    }

    private getTerraformFixtureTemplateFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'rule-builder', 'src', 'fixtures', 'templates', 'terraform');
    }

    private getTerraformFixtureResourceFilePath(): string {
        return path.join(this.srtRootFolderPath, 'rule-builder', 'src', 'shared', 'rules', this.service, this.safeRuleId, `${this.safeRuleId}.tf`);
    }

    private getCloudFormationFixtureOutputFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'fixtures', this.safeRuleId, 'cfn');
    }

    private getCloudFormationFixtureTemplateFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'rule-builder', 'src', 'fixtures', 'templates', 'cfn');
    }

    private getCloudFormationFixtureResourceFilePath(): string {
        return path.join(this.srtRootFolderPath, 'rule-builder', 'src', 'shared', 'rules', this.service, this.safeRuleId, `${this.safeRuleId}.yaml`);
    }

    private getSafeRuleId(): string {
        return this.ruleId.replace(/[^A-Za-z0-9_.-]/g, '_').toLowerCase();
    }

    private getRuleFolderPath(): string {
        return path.join(this.srtRootFolderPath, 'src', 'assess', 'scanning', 'security-matrix', 'rules', this.service, this.safeRuleId);
    }

    private getRuleControlFilePath(): string {
        return path.join(this.ruleFolderPath, `${this.safeRuleId}.control.ts`);
    }

    private getRuleAdapterBaseFilePath(): string {
        return path.join(this.ruleFolderPath, `${this.safeRuleId}.adapter.ts`);
    }

    private getRuleAdapterCfnFilePath(): string {
        return path.join(this.ruleFolderPath, `${this.safeRuleId}.adapter.cfn.ts`);
    }
    
    private getRuleAdapterTfFilePath(): string {
        return path.join(this.ruleFolderPath, `${this.safeRuleId}.adapter.tf.ts`);
    }

    private getSecurityControlBaseFilePath(): string {
        return path.join(this.srtRootFolderPath, 'src', 'assess', 'scanning', 'security-matrix', 'controls', 'security-control.ts');
    }

    private getSecurityControlTypesFilePath(): string {
        return path.join(this.srtRootFolderPath, 'src', 'assess', 'scanning', 'security-matrix', 'controls', 'types.ts');
    }

    private getServiceControlsIndexPath(): string {
        return path.join(this.srtRootFolderPath, 'src', 'assess', 'scanning', 'security-matrix', 'rules', this.service, 'controls', 'index.ts');
    }

    private getControlsRegistryPath(): string {
        return path.join(this.srtRootFolderPath, 'src', 'assess', 'scanning', 'security-matrix', 'rules', 'controls-registry.ts');
    }

    private getRuleFixtureFilePath(): string {
        return path.join(this.getRootFixtureFolderPath(), 'fixture-stack.ts');
    }
}
