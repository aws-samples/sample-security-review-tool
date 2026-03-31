import { Template } from 'cloudform-types';
import { ScanResult } from '../base-scanner.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';

type Resource = NonNullable<Template['Resources']>[string];
export type { Resource };

export interface CloudFormationResource {
  Type: string;
  Properties: Record<string, any>;
  LogicalId: string;
  Metadata?: Record<string, any>;
}

export abstract class BaseRule {
  constructor(public id: string, public priority: 'HIGH' | 'MEDIUM' | 'LOW', public description: string, public applicableResourceTypes: string[]) { }

  public appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  // evaluate() is the legacy implementation method for rule evaluation. Do not use in new rules.
  public abstract evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null;

  // evaluateResource() is the new implementation method that enables simpler rule evaluation. Use in new rules.
  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null | undefined {
    return undefined;
  }

  // createScanResult is the legacy implementation method for creating scan results. Do not use in new rules.
  protected createScanResult(resource: CloudFormationResource, stackName: string, issue: string, fix?: string): ScanResult {
    return {
      source: 'security-matrix',
      path: stackName,
      resourceType: resource.Type,
      resourceName: resource.LogicalId,
      issue: issue,
      fix: fix,
      priority: this.priority.toUpperCase(),
      check_id: this.id,
      status: 'Open',
      cdkPath: resource.Metadata?.['aws:cdk:path'],
      isCustomResource: this.isCustomResource(resource)
    };
  }

  // createResult is the new implementation method that enables simpler rule evaluation. Use in new rules.
  protected createResult(stackName: string, template: Template, resource: Resource, issue: string, fix: string): ScanResult {
    const resourceId = template.Resources ? Object.keys(template.Resources).find(key => template.Resources![key] === resource) : undefined;

    if (!resourceId) throw new Error('Resource not found in template.');

    return {
      source: 'security-matrix',
      path: stackName,
      resourceType: resource.Type,
      resourceName: resourceId,
      issue: issue,
      fix: fix,
      priority: this.priority.toUpperCase(),
      check_id: this.id,
      status: 'Open',
      cdkPath: resource.Metadata?.['aws:cdk:path'],
      isCustomResource: this.isCustomResource(resource)
    };
  }

  private isCustomResource(resource: Resource): boolean | undefined {
    try {
      const cdkPath = resource.Metadata?.['aws:cdk:path'];
      if (!cdkPath) return false;

      const lowerCdkPath = cdkPath.toLowerCase();
      const pathSegments = lowerCdkPath.split('/');

      return lowerCdkPath.includes('custom::') ||
        pathSegments[1]?.startsWith('logretention') ||
        pathSegments[1]?.startsWith('bucketnotificationshandler') ||
        pathSegments[1]?.includes('679f53fac002430cb0da5b7982bd2287'); // CDK Custom Resource Provider ID
    } catch (error) {
      SrtLogger.logError('Error checking custom resource', error as Error);
    }
  }
}
