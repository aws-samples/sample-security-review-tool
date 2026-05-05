import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * KMS7: Configure monitoring infrastructure for KMS events
 * 
 * Security Principle: Monitoring & Alerting
 * 
 * This rule ensures that when KMS keys are deployed, appropriate monitoring
 * infrastructure exists to capture and alert on KMS events.
 * 
 * Risk: KMS keys without monitoring infrastructure cannot detect unauthorized
 * access, key misuse, or compliance violations.
 */
export class KMS007Rule extends BaseRule {
    constructor() {
        super(
            'KMS-007',
            'HIGH',
            'KMS key deployed without monitoring infrastructure for events and compliance',
            ['AWS::KMS::Key']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        if (!this.hasMonitoringInfrastructure(template)) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Add EventBridge rule with EventPattern source "aws.kms" and Lambda function target for KMS event monitoring. The Lambda function should have X-Ray tracing enabled. The Lambda function should have CloudWatch Alarms for the following Lambda metrics: Errors, Throttles, Duration, Invocations, ConcurrentExecutions, and DeadLetterErrors.'
            );
        }

        return null;
    }

    private hasMonitoringInfrastructure(template: Template): boolean {
        if (!template.Resources) return false;

        // Check for EventBridge rules monitoring KMS with proper targets
        const hasKMSEventRule = Object.values(template.Resources).some((resource: any) => 
            resource.Type === 'AWS::Events::Rule' && 
            this.isKMSEventRule(resource as Resource) &&
            this.hasProperTargets(resource as Resource)
        );

        // Check for Security Hub integration (Config rules or Security Hub itself)
        const hasSecurityHubIntegration = Object.values(template.Resources).some((resource: any) => 
            (resource.Type === 'AWS::Config::ConfigRule' && this.isKMSConfigRule(resource as Resource)) ||
            resource.Type === 'AWS::SecurityHub::Hub'
        );

        return hasKMSEventRule || hasSecurityHubIntegration;
    }

    private hasProperTargets(resource: Resource): boolean {
        const targets = resource.Properties?.Targets;
        if (!targets || !Array.isArray(targets) || targets.length === 0) {
            return false;
        }

        // Check if targets include Lambda functions for monitoring
        return targets.some((target: any) => {
            const arn = target.Arn;
            if (typeof arn === 'string') {
                return arn.includes(':lambda:');
            }
            
            // Handle CloudFormation references
            if (typeof arn === 'object' && (arn.Ref || arn['Fn::GetAtt'])) {
                return true; // Assume proper target if using references
            }
            
            return false;
        });
    }

    private isKMSEventRule(resource: Resource): boolean {
        const eventPattern = resource.Properties?.EventPattern;
        if (!eventPattern) return false;

        // Check if monitoring KMS events
        const source = eventPattern.source;
        if (Array.isArray(source) && source.includes('aws.kms')) {
            return true;
        }
        if (source === 'aws.kms') {
            return true;
        }

        return false;
    }

    private isKMSConfigRule(resource: Resource): boolean {
        const source = resource.Properties?.Source;
        if (!source) return false;

        // Check for AWS managed Config rules for KMS
        const kmsConfigRules = [
            'cmk-backing-key-rotation-enabled',
            'kms-cmk-not-scheduled-for-deletion',
            'encrypted-volumes'
        ];

        return kmsConfigRules.some(rule => 
            source.SourceIdentifier && source.SourceIdentifier.includes(rule)
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }
}

export default new KMS007Rule();