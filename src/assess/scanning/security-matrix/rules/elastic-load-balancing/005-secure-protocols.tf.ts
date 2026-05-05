import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElb005Rule extends BaseTerraformRule {
  private readonly WEAK_SSL_POLICIES = [
    'ELBSecurityPolicy-TLS13-1-1-2021-06',
    'ELBSecurityPolicy-TLS13-1-0-2021-06',
    'ELBSecurityPolicy-TLS-1-1-2017-01',
    'ELBSecurityPolicy-2016-08',
    'ELBSecurityPolicy-2015-05',
    'ELBSecurityPolicy-TLS13-1-1-FIPS-2023-04',
    'ELBSecurityPolicy-TLS13-1-0-FIPS-2023-04',
    'ELBSecurityPolicy-FS-1-1-2019-08',
    'ELBSecurityPolicy-FS-2018-06',
  ];

  constructor() {
    super('ELB-005', 'HIGH', 'Load balancer listener uses insecure protocols or weak SSL/TLS versions', ['aws_lb_listener', 'aws_elb']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_lb_listener') {
      const protocol = (resource.values?.protocol || '').toUpperCase();

      if (protocol === 'HTTP' || protocol === 'TCP') {
        return this.createScanResult(resource, projectName, this.description, 'Use HTTPS or TLS protocol instead of ' + protocol + ' for secure communication.');
      }

      if (protocol === 'HTTPS' || protocol === 'TLS') {
        const sslPolicy = resource.values?.ssl_policy;
        if (!sslPolicy || this.WEAK_SSL_POLICIES.includes(sslPolicy)) {
          return this.createScanResult(resource, projectName, this.description, 'Set ssl_policy to "ELBSecurityPolicy-TLS-1-2-2017-01" or a newer secure policy.');
        }
      }
    }

    if (resource.type === 'aws_elb') {
      const listeners = resource.values?.listener;
      if (Array.isArray(listeners)) {
        for (const listener of listeners) {
          const protocol = (listener.lb_protocol || '').toUpperCase();
          if (protocol === 'HTTP' || protocol === 'TCP') {
            return this.createScanResult(resource, projectName, this.description, 'Use HTTPS or SSL protocol instead of ' + protocol + '.');
          }
        }
      }
    }

    return null;
  }
}

export default new TfElb005Rule();
