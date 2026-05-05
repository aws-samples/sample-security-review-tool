import { ScanResult } from '../types.js';

export interface TerraformResource {
  type: string;
  name: string;
  address: string;
  values: Record<string, any>;
}

export abstract class BaseTerraformRule {
  constructor(
    public id: string,
    public priority: 'HIGH' | 'MEDIUM' | 'LOW',
    public description: string,
    public applicableResourceTypes: string[]
  ) {}

  public appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  public abstract evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null;

  protected createScanResult(resource: TerraformResource, projectName: string, issue: string, fix?: string): ScanResult {
    return {
      source: 'terraform-matrix',
      path: projectName,
      resourceType: resource.type,
      resourceName: resource.address,
      issue,
      fix,
      priority: this.priority.toUpperCase(),
      check_id: this.id,
      status: 'Open'
    };
  }
}
