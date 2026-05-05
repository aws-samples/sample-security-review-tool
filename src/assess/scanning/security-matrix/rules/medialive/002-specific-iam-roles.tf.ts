import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaLive002Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIALIVE-002', 'HIGH', 'MediaLive channel must specify a dedicated IAM role', ['aws_medialive_channel']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_medialive_channel') {
      const roleArn = resource.values?.role_arn;
      if (!roleArn) {
        return this.createScanResult(resource, projectName, this.description, 'Set role_arn with a dedicated IAM role for this MediaLive channel.');
      }

      const otherChannels = allResources.filter(r =>
        r.type === 'aws_medialive_channel' &&
        r.address !== resource.address &&
        r.values?.role_arn === roleArn
      );

      if (otherChannels.length > 0) {
        return this.createScanResult(resource, projectName, 'MediaLive channel is sharing an IAM role with another channel', 'Create a dedicated IAM role for each MediaLive channel.');
      }
    }

    return null;
  }
}

export default new TfMediaLive002Rule();
