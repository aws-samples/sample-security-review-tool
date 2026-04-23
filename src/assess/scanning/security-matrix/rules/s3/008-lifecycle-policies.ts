import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * S8 Rule: Ensure S3 buckets have lifecycle policies configured.
 *
 * Documentation: "The solution should use a lifecycle policy configuration to manage S3 objects during their lifetime."
 */
export class S3008Rule extends BaseRule {
  constructor() {
    super(
      'S3-008',
      'HIGH',
      'S3 bucket lacks lifecycle policy',
      ['AWS::S3::Bucket']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type)) return null;

    const resolver = new CloudFormationResolver(allResources);
    const rawLifecycleConfiguration = resource.Properties?.LifecycleConfiguration;

    if (rawLifecycleConfiguration == null) {
      return this.createScanResult(resource, stackName, this.description, this.buildAddConfigFix());
    }

    if (resolver.resolve(rawLifecycleConfiguration).isIntrinsicFunction) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        'Use explicit configuration instead of CloudFormation intrinsic functions for lifecycle configuration.'
      );
    }

    const rules = rawLifecycleConfiguration.Rules;
    if (!Array.isArray(rules) || rules.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}: LifecycleConfiguration has no rules`,
        this.buildAddConfigFix()
      );
    }

    if (!this.hasEnabledRule(rules, resolver)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}: LifecycleConfiguration has no enabled rules`,
        this.buildAddConfigFix()
      );
    }

    return null;
  }

  private hasEnabledRule(rules: any[], resolver: CloudFormationResolver): boolean {
    return rules.some(rule => {
      const status = resolver.resolve(rule?.Status);
      // Treat unresolved Status (intrinsic function) as enabled to avoid false positives.
      if (!status.isResolved) return true;
      return status.value === 'Enabled';
    });
  }

  private buildAddConfigFix(): string {
    return 'Add a LifecycleConfiguration to the S3 bucket that transitions objects to STANDARD_IA after 30 days. For CDK sources, edit the CDK source (not cdk.out/*)';
  }
}

export default new S3008Rule();
