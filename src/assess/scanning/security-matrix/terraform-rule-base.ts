import { ScanResult } from '../types.js';

export interface TerraformResource {
  type: string;
  name: string;
  address: string;
  values: Record<string, any>;
}

const UNRESOLVED_MARKER = '__unresolved__:';

export function unresolved(expression: string): string {
  return `${UNRESOLVED_MARKER}${expression}`;
}

/**
 * A value the scanner could not work out: a variable with no reachable default, a local, a
 * data source, a module output, or any expression left partly interpolated. The configuration
 * is unknown rather than wrong, so a rule must not report a finding on one.
 */
export function isUnresolved(value: unknown): boolean {
  return typeof value === 'string' && (value.startsWith(UNRESOLVED_MARKER) || value.includes('${'));
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
