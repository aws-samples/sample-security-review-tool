import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT032Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-032', 'HIGH', 'IoT policy does not enforce separation of duties', ['aws_iot_policy']);
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

        const hasAdmin = actions.some((a: string) => a.includes('CreateThing') || a.includes('DeleteThing') || a.includes('UpdateThing'));
        const hasData = actions.some((a: string) => a.includes('Publish') || a.includes('Subscribe') || a.includes('Receive'));

        if (hasAdmin && hasData) {
          return this.createScanResult(resource, projectName, this.description, 'Separate administrative actions (Create/Delete/Update) from data plane actions (Publish/Subscribe) into different IoT policies.');
        }
      }
    }

    return null;
  }
}

export default new TfIoT032Rule();
