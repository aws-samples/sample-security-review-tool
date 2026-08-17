import type { ControlAdapter, CfnContext, Finding, IacContext, Priority, Resource, ScanResult, TfContext } from './types.js';
import { SrtLogger } from '../../../../shared/logging/srt-logger.js';
import type { Remediation } from '../../remediation/types.js';

export const RELATED_RULES_HEADING = '\n\nAdditional constraints (your fix must also satisfy these related rules):\n\n';

export interface SecurityControlMetadata<TAdapter extends ControlAdapter, TFindingKey extends string> {
    readonly id: string;
    readonly priority: Priority;
    readonly description: string;
    readonly findings: Readonly<Record<TFindingKey, Finding<TAdapter>>>;
    readonly relatedRules?: readonly Remediation[];
    readonly supersedes?: readonly string[];
}

export abstract class SecurityControl<
    TAdapter extends ControlAdapter = ControlAdapter,
    TFindingKey extends string = string,
> implements Remediation {
    public readonly id: string;
    public readonly priority: Priority;
    public readonly description: string;
    public readonly findings: Readonly<Record<TFindingKey, Finding<TAdapter>>>;
    public readonly relatedRules: readonly Remediation[];
    public readonly supersedes: readonly string[];

    constructor(metadata: SecurityControlMetadata<TAdapter, TFindingKey>) {
        this.id = metadata.id;
        this.priority = metadata.priority;
        this.description = metadata.description;
        this.findings = metadata.findings;
        this.relatedRules = metadata.relatedRules ?? [];
        this.supersedes = metadata.supersedes ?? [];
    }

    public get remediation(): string {
        const remediations = Object.keys(this.findings)
            .map(key => this.findings[key as TFindingKey].remediation);
        return [...new Set(remediations)].join('\n\n');
    }

    protected abstract evaluate(adapter: TAdapter): TFindingKey | null;

    public run(adapter: TAdapter, context: IacContext): ScanResult | null {
        const findingKey = this.evaluate(adapter);
        if (findingKey === null) return null;
        const finding = this.findings[findingKey];
        const remediation = this.buildRemediation(finding.remediation);
        const issue = typeof finding.issue === 'function' ? finding.issue(adapter) : finding.issue;
        const result = this.buildScanResult(context, adapter, issue, remediation);
        if (finding.manualFixRequired) result.manualFixRequired = true;
        return result;
    }

    private buildRemediation(primaryRemediation: string): string {
        const related = this.relatedRules.filter(rule => rule.remediation.trim().length > 0);
        if (related.length === 0) return primaryRemediation;
        const relatedGuidance = related.map(rule => this.describeRelatedRule(rule)).join('\n\n');
        return `${primaryRemediation}${RELATED_RULES_HEADING}${relatedGuidance}`;
    }

    private describeRelatedRule(rule: Remediation): string {
        const prefix = rule.description ? `[${rule.id}] ${rule.description}:` : `[${rule.id}]`;
        return `${prefix} ${rule.remediation}`;
    }

    private buildScanResult(context: IacContext, adapter: TAdapter, issue: string, remediation: string): ScanResult {
        if ('stackName' in context) {
            const cfn = context as CfnContext;
            return {
                source: 'security-matrix',
                path: cfn.stackName,
                resourceType: adapter.resourceType,
                resourceName: adapter.resourceId,
                issue,
                fix: remediation,
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
            issue,
            fix: remediation,
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
