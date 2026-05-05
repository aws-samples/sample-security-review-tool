import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH1 Rule: Provision the OpenSearch service domain inside a VPC.
 */
export class ESH001Rule extends BaseRule {
  constructor() {
    super(
      'ESH-001',
      'HIGH',
      'OpenSearch domain not deployed in VPC',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const vpcOptions = resource.Properties?.VPCOptions;

    if (!vpcOptions || !vpcOptions.SubnetIds) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add VPCOptions with SubnetIds to deploy domain in VPC.`
      );
    }

    return null;
  }
}

export default new ESH001Rule();