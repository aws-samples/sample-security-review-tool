import { AdapterFactory, CfnContext, Resource, Template } from '../../../controls/types.js';
import { Lambda012Adapter } from './lambda-012.adapter.js';

const LAMBDA_RESOURCE_TYPES = ['AWS::Lambda::Function', 'AWS::Serverless::Function'];

export class Lambda012CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = LAMBDA_RESOURCE_TYPES;

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Lambda012CfnAdapter {
    return new Lambda012CfnAdapter(context);
  }
}

class Lambda012CfnAdapter implements Lambda012Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly sharesExecutionRole: boolean;

  constructor(ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
    this.sharesExecutionRole = this.computeSharesExecutionRole(ctx);
  }

  private computeSharesExecutionRole(ctx: CfnContext): boolean {
    const role = this.getRole(ctx.resource);
    if (!role) return false;

    const otherResources = this.findOtherResources(ctx.template, ctx.logicalId);
    return otherResources.some(other => this.resourceReferencesRole(other, role));
  }

  private getRole(resource: Resource): string | undefined {
    const role = resource?.Properties?.Role;
    return typeof role === 'string' ? role : undefined;
  }

  private findOtherResources(template: Template, currentLogicalId: string): Resource[] {
    const resources = template.Resources ?? {};
    return Object.entries(resources)
      .filter(([logicalId]) => logicalId !== currentLogicalId)
      .map(([, resource]) => resource)
      .filter(resource => LAMBDA_RESOURCE_TYPES.includes(resource.Type));
  }

  private resourceReferencesRole(resource: Resource, role: string): boolean {
    return this.containsValue(resource?.Properties, role);
  }

  private containsValue(node: unknown, target: string): boolean {
    if (node === null || node === undefined) return false;
    if (typeof node === 'string') return node === target;
    if (Array.isArray(node)) return node.some(item => this.containsValue(item, target));
    if (typeof node === 'object') return Object.values(node).some(value => this.containsValue(value, target));
    return false;
  }
}
