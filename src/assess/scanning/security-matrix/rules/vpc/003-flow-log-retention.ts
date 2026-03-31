import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * VPC-003: Flow log destinations must have retention periods configured
 *
 * Flow logs capture network traffic for troubleshooting and security analysis.
 * Without retention periods, logs accumulate indefinitely causing:
 * - Unbounded storage costs
 * - Compliance violations (data retention policies)
 * - Difficulty managing log data lifecycle
 *
 * Validates retention for all destination types:
 * - CloudWatch Logs: RetentionInDays on AWS::Logs::LogGroup
 * - S3: Lifecycle rules on AWS::S3::Bucket
 * - Kinesis Data Firehose: Assumed compliant (retention managed externally)
 */
export class Vpc003Rule extends BaseRule {
    constructor() {
        super(
            'VPC-003',
            'HIGH',
            'Flow log destination does not have a retention period configured',
            ['AWS::EC2::FlowLog']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const destinationType = this.getDestinationType(resource);
        const logDestination = resource.Properties?.LogDestination;
        const logGroupName = resource.Properties?.LogGroupName;

        if (destinationType === 'cloud-watch-logs') {
            return this.validateCloudWatchDestination(stackName, template, resource, logGroupName, logDestination);
        }

        if (destinationType === 's3') {
            return this.validateS3Destination(stackName, template, resource, logDestination);
        }

        // Kinesis Data Firehose: retention managed externally, assume compliant
        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private getDestinationType(resource: Resource): string {
        const explicitType = resource.Properties?.LogDestinationType;
        if (explicitType) return explicitType;

        // Default is cloud-watch-logs per AWS docs
        return 'cloud-watch-logs';
    }

    private validateCloudWatchDestination(stackName: string, template: Template, resource: Resource, logGroupName: any, logDestination: any): ScanResult | null {
        const logGroup = this.findLogGroup(template, logGroupName, logDestination);

        if (!logGroup) {
            // Log group defined externally or via intrinsic - can't validate
            return null;
        }

        if (!this.hasRetentionInDays(logGroup)) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Set RetentionInDays on the associated AWS::Logs::LogGroup resource. Valid values: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653'
            );
        }

        return null;
    }

    private validateS3Destination(stackName: string, template: Template, resource: Resource, logDestination: any): ScanResult | null {
        const bucket = this.findS3Bucket(template, logDestination);

        if (!bucket) {
            // Bucket defined externally or via intrinsic - can't validate
            return null;
        }

        if (!this.hasLifecycleRules(bucket)) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Add LifecycleConfiguration with expiration rules to the S3 bucket receiving flow logs'
            );
        }

        return null;
    }

    private findLogGroup(template: Template, logGroupName: any, logDestination: any): Resource | null {
        if (!template.Resources) return null;

        // Direct reference via LogGroupName
        if (logGroupName && typeof logGroupName === 'object' && logGroupName.Ref) {
            const resource = template.Resources[logGroupName.Ref];
            if (resource?.Type === 'AWS::Logs::LogGroup') return resource;
        }

        // GetAtt reference to log group ARN
        if (logDestination && typeof logDestination === 'object' && logDestination['Fn::GetAtt']) {
            const getAtt = logDestination['Fn::GetAtt'];
            const resourceId = Array.isArray(getAtt) ? getAtt[0] : getAtt.split('.')[0];
            const resource = template.Resources[resourceId];
            if (resource?.Type === 'AWS::Logs::LogGroup') return resource;
        }

        // Sub reference pattern
        if (logDestination && typeof logDestination === 'object' && logDestination['Fn::Sub']) {
            const subValue = logDestination['Fn::Sub'];
            const subString = Array.isArray(subValue) ? subValue[0] : subValue;
            if (typeof subString === 'string') {
                const match = subString.match(/\$\{(\w+)(?:\.[^}]+)?\}/);
                if (match) {
                    const resource = template.Resources[match[1]];
                    if (resource?.Type === 'AWS::Logs::LogGroup') return resource;
                }
            }
        }

        return null;
    }

    private findS3Bucket(template: Template, logDestination: any): Resource | null {
        if (!template.Resources) return null;

        // GetAtt reference to bucket ARN
        if (logDestination && typeof logDestination === 'object' && logDestination['Fn::GetAtt']) {
            const getAtt = logDestination['Fn::GetAtt'];
            const resourceId = Array.isArray(getAtt) ? getAtt[0] : getAtt.split('.')[0];
            const resource = template.Resources[resourceId];
            if (resource?.Type === 'AWS::S3::Bucket') return resource;
        }

        // Sub reference pattern
        if (logDestination && typeof logDestination === 'object' && logDestination['Fn::Sub']) {
            const subValue = logDestination['Fn::Sub'];
            const subString = Array.isArray(subValue) ? subValue[0] : subValue;
            if (typeof subString === 'string') {
                const match = subString.match(/\$\{(\w+)(?:\.[^}]+)?\}/);
                if (match) {
                    const resource = template.Resources[match[1]];
                    if (resource?.Type === 'AWS::S3::Bucket') return resource;
                }
            }
        }

        // Ref to bucket
        if (logDestination && typeof logDestination === 'object' && logDestination.Ref) {
            const resource = template.Resources[logDestination.Ref];
            if (resource?.Type === 'AWS::S3::Bucket') return resource;
        }

        return null;
    }

    private hasRetentionInDays(logGroup: Resource): boolean {
        return logGroup.Properties?.RetentionInDays !== undefined;
    }

    private hasLifecycleRules(bucket: Resource): boolean {
        const lifecycleConfig = bucket.Properties?.LifecycleConfiguration;
        if (!lifecycleConfig?.Rules) return false;

        const rules = lifecycleConfig.Rules;
        return Array.isArray(rules) && rules.length > 0;
    }
}

export default new Vpc003Rule();
