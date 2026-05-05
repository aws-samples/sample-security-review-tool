import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT016Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-016', 'HIGH', 'IoT policy allows overly broad public access', ['aws_iot_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_policy') {
      const policy = resource.values?.policy;
      if (!policy) return null;

      let policyObj: any;
      if (typeof policy === 'string') {
        try {
          policyObj = JSON.parse(policy);
        } catch {
          return null;
        }
      } else {
        policyObj = policy;
      }

      if (!policyObj?.Statement) return null;
      const statements = Array.isArray(policyObj.Statement) ? policyObj.Statement : [policyObj.Statement];

      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];

        if (resources.includes('*') && (actions.includes('iot:*') || actions.includes('iot:Publish'))) {
          return this.createScanResult(resource, projectName, this.description, 'Restrict IoT policy resources to specific topic ARNs instead of using wildcard "*".');
        }
      }
    }

    return null;
  }
}

export default new TfIoT016Rule();
