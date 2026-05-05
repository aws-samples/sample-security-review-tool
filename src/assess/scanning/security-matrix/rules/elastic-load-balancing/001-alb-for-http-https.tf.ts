import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElb001Rule extends BaseTerraformRule {
  constructor() {
    super('ELB-001', 'HIGH', 'Classic Load Balancer is used for HTTP/HTTPS traffic instead of Application Load Balancer', ['aws_elb']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elb') {
      const listeners = resource.values?.listener;
      if (Array.isArray(listeners)) {
        const hasHttpHttps = listeners.some((listener: any) => {
          const protocol = (listener.lb_protocol || '').toUpperCase();
          return protocol === 'HTTP' || protocol === 'HTTPS';
        });

        if (hasHttpHttps) {
          return this.createScanResult(resource, projectName, this.description, 'Replace aws_elb with aws_lb (type = "application") for HTTP/HTTPS traffic.');
        }
      }
    }

    return null;
  }
}

export default new TfElb001Rule();
