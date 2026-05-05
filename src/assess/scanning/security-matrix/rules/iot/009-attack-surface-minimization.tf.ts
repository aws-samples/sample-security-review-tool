import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT009Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-009', 'HIGH', 'IoT policy has overly permissive actions that expand the attack surface', ['aws_iot_policy']);
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
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];

        if (actions.includes('iot:*') && resources.includes('*')) {
          return this.createScanResult(resource, projectName, this.description, 'Replace wildcard "iot:*" action with specific actions like "iot:Connect", "iot:Publish", "iot:Subscribe".');
        }
      }
    }

    return null;
  }
}

export default new TfIoT009Rule();
