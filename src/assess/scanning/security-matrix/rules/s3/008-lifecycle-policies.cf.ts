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
    const lifecycleConfiguration = resolver.resolve(resource.Properties?.LifecycleConfiguration);

    // Check if lifecycle configuration exists
    if (lifecycleConfiguration.isResolved && lifecycleConfiguration.value) {
      return null;
    }

    // If lifecycle configuration is an intrinsic function, we cannot validate it at scan time
    if (lifecycleConfiguration.isIntrinsicFunction) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Use explicit configuration instead of CloudFormation intrinsic functions for lifecycle configuration.`
      );
    }

    // If lifecycle configuration is not set or not resolved, we need to flag it
    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `Configure a lifecycle policy to manage S3 objects during their lifetime.`
    );
  }
}

export default new S3008Rule();
