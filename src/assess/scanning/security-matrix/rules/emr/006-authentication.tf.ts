import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEmr006Rule extends BaseTerraformRule {
  constructor() {
    super('EMR-006', 'HIGH', 'EMR cluster does not have authentication configured (EC2 Key Pair or Kerberos)', ['aws_emr_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_emr_cluster') {
      const keyName = resource.values?.ec2_attributes?.key_name
        || resource.values?.ec2_attributes?.[0]?.key_name;
      const kerberosAttributes = resource.values?.kerberos_attributes;

      if (!keyName && !kerberosAttributes) {
        return this.createScanResult(resource, projectName, this.description, 'Set ec2_attributes.key_name for SSH key authentication or add kerberos_attributes for Kerberos authentication.');
      }
    }

    return null;
  }
}

export default new TfEmr006Rule();
