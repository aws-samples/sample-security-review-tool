import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT007Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-007', 'MEDIUM', 'IoT topic rule forwards data to third-party destinations without proper access control', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasHttpAction = resource.values?.http;
      if (Array.isArray(hasHttpAction) && hasHttpAction.length > 0) {
        for (const httpAction of hasHttpAction) {
          if (!httpAction.confirmation_url) {
            return this.createScanResult(resource, projectName, this.description, 'Add confirmation_url to http actions for third-party endpoint verification.');
          }
        }
      }
    }

    return null;
  }
}

export default new TfIoT007Rule();
