import { ControlAdapter, CfnContext, ControlFinding, IacContext, IacRemediation, Priority, RemediationScenario, Resource, ScanResult, TfContext } from './types.js';
import { SrtLogger } from '../../../../shared/logging/srt-logger.js';

export interface SecurityControlMetadata {
    readonly id: string;
    readonly priority: Priority;
    readonly description: string;
    readonly remediationScenarios: RemediationScenario[];
}

export abstract class SecurityControl<TAdapter extends ControlAdapter = ControlAdapter> {
    public readonly id: string;
    public readonly priority: Priority;
    public readonly description: string;
    public readonly remediationScenarios: RemediationScenario[];

    constructor(metadata: SecurityControlMetadata) {
        this.id = metadata.id;
        this.priority = metadata.priority;
        this.description = metadata.description;
        this.remediationScenarios = metadata.remediationScenarios;
    }

    protected abstract evaluate(adapter: TAdapter): ControlFinding | null;

    public run(adapter: TAdapter, context: IacContext): ScanResult | null {
        const finding = this.evaluate(adapter);
        if (!finding) return null;
        const fix = this.buildRemediation(adapter, finding.scenario);
        return this.buildScanResult(context, adapter, finding, fix);
    }

    private buildRemediation(adapter: TAdapter, scenario: string): string {
        const def = this.remediationScenarios.find(s => s.scenario === scenario);
        const iac: IacRemediation | null = adapter.getRemediation(scenario);
        if (def && iac) return `${def.intent}\n\n${iac.guidance}`;
        return def?.intent ?? '';
    }

    private buildScanResult(context: IacContext, adapter: TAdapter, finding: ControlFinding, fix: string): ScanResult {
        if ('stackName' in context) {
            const cfn = context as CfnContext;
            return {
                source: 'security-matrix',
                path: cfn.stackName,
                resourceType: adapter.resourceType,
                resourceName: adapter.resourceId,
                issue: finding.issue ?? this.description,
                fix,
                priority: this.priority.toUpperCase(),
                check_id: this.id,
                status: 'Open',
                cdkPath: cfn.resource.Metadata?.['aws:cdk:path'],
                isCustomResource: this.isCustomResource(cfn.resource),
            };
        }

        const tf = context as TfContext;
        return {
            source: 'terraform-matrix',
            path: tf.projectName,
            resourceType: adapter.resourceType,
            resourceName: adapter.resourceId,
            issue: finding.issue ?? this.description,
            fix,
            priority: this.priority.toUpperCase(),
            check_id: this.id,
            status: 'Open',
        };
    }

    private isCustomResource(resource: Resource): boolean | undefined {
        try {
            const cdkPath = resource.Metadata?.['aws:cdk:path'];
            if (!cdkPath) return false;
            const lowerCdkPath = cdkPath.toLowerCase();
            const pathSegments = lowerCdkPath.split('/');
            return lowerCdkPath.includes('custom::') ||
                pathSegments[1]?.startsWith('logretention') ||
                pathSegments[1]?.startsWith('bucketnotificationshandler') ||
                pathSegments[1]?.includes('679f53fac002430cb0da5b7982bd2287');
        } catch (error) {
            SrtLogger.logError('Error checking custom resource', error as Error);
        }
    }
}
