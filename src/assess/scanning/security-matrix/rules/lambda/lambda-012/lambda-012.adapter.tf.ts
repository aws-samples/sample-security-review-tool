import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Lambda012Adapter } from './lambda-012.adapter.js';

const LAMBDA_RESOURCE_TYPE = 'aws_lambda_function';

export class Lambda012TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [LAMBDA_RESOURCE_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Lambda012TfAdapter {
    return new Lambda012TfAdapter(context);
  }
}

class Lambda012TfAdapter implements Lambda012Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly sharesExecutionRole: boolean;

  constructor(ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
    this.sharesExecutionRole = this.computeSharesExecutionRole(ctx);
  }

  private computeSharesExecutionRole(ctx: TfContext): boolean {
    const role = this.getRole(ctx.resource);
    if (!role) return false;

    const otherResources = this.findOtherResources(ctx.allResources, ctx.resource.address);
    return otherResources.some(other => this.resourceReferencesRole(other, role));
  }

  private getRole(resource: TerraformResource): string | undefined {
    const role = (resource as { values?: { role?: unknown } })?.values?.role;
    return typeof role === 'string' ? role : undefined;
  }

  private findOtherResources(allResources: TerraformResource[], currentAddress: string): TerraformResource[] {
    return allResources.filter(resource => resource.address !== currentAddress);
  }

  private resourceReferencesRole(resource: TerraformResource, role: string): boolean {
    if (this.isTheRoleItself(resource, role)) return false;
    const values = (resource as { values?: unknown })?.values;
    return this.containsValue(values, role);
  }

  private isTheRoleItself(resource: TerraformResource, role: string): boolean {
    const values = (resource as { values?: { arn?: unknown; id?: unknown } })?.values;
    if (!values) return false;
    return values.arn === role || values.id === role;
  }

  private containsValue(node: unknown, target: string): boolean {
    if (node === null || node === undefined) return false;
    if (typeof node === 'string') return node === target;
    if (Array.isArray(node)) return node.some(item => this.containsValue(item, target));
    if (typeof node === 'object') return Object.values(node).some(value => this.containsValue(value, target));
    return false;
  }
}
