import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Lambda005Adapter } from './lambda-005.adapter.js';
import { hasWildcardActionAndResource, isBroadManagedPolicy, trustsLambdaServicePrincipal } from './lambda-005.policy.js';

const ATTACHMENT_TYPES = ['aws_iam_role_policy_attachment', 'aws_iam_policy_attachment'];

export class Lambda005TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_iam_role', 'aws_iam_role_policy', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_iam_policy_attachment', 'aws_lambda_function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Lambda005TfAdapter {
    return new Lambda005TfAdapter(context);
  }
}

class Lambda005TfAdapter implements Lambda005Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  isLambdaExecutionRole(): boolean {
    if (this.resourceType !== 'aws_iam_role') return false;
    if (trustsLambdaServicePrincipal(this.values(this.ctx.resource)['assume_role_policy'])) return true;
    return this.resourcesOfType('aws_lambda_function')
      .some(fn => this.referencesThisRole(this.values(fn)['role']));
  }

  grantsWildcardActionOnAllResources(): boolean {
    return this.inlinePolicyDocuments().some(hasWildcardActionAndResource);
  }

  usesOverlyBroadManagedPolicy(): boolean {
    return this.attachedPolicyReferences().some(isBroadManagedPolicy);
  }

  private inlinePolicyDocuments(): unknown[] {
    const embedded = this.asArray(this.values(this.ctx.resource)['inline_policy'])
      .map(block => this.asRecord(block)['policy']);
    const separate = this.resourcesOfType('aws_iam_role_policy')
      .filter(policy => this.referencesThisRole(this.values(policy)['role']))
      .map(policy => this.values(policy)['policy']);
    return [...embedded, ...separate];
  }

  private attachedPolicyReferences(): unknown[] {
    return this.attachmentsForThisRole().flatMap(attachment => {
      const policyArn = this.values(attachment)['policy_arn'];
      const managed = this.resolveManagedPolicyName(policyArn);
      return managed === null ? [policyArn] : [managed];
    });
  }

  private attachmentsForThisRole(): TerraformResource[] {
    return ATTACHMENT_TYPES.flatMap(type => this.resourcesOfType(type))
      .filter(attachment => this.attachmentTargetsThisRole(attachment));
  }

  private attachmentTargetsThisRole(attachment: TerraformResource): boolean {
    const values = this.values(attachment);
    if (this.referencesThisRole(values['role'])) return true;
    return this.asArray(values['roles']).some(role => this.referencesThisRole(role));
  }

  /** Attachments may point at a policy declared in the same plan; use its name for breadth checks. */
  private resolveManagedPolicyName(policyArn: unknown): unknown {
    if (typeof policyArn !== 'string') return null;
    const declared = this.resourcesOfType('aws_iam_policy')
      .find(policy => policy.address === policyArn);
    return declared ? this.values(declared)['name'] ?? declared.name : null;
  }

  private referencesThisRole(reference: unknown): boolean {
    if (typeof reference !== 'string') return false;
    if (reference === this.ctx.resource.address) return true;
    const roleName = this.values(this.ctx.resource)['name'];
    return typeof roleName === 'string' && reference === roleName;
  }

  private resourcesOfType(type: string): TerraformResource[] {
    return this.ctx.allResources.filter(resource => resource?.type === type);
  }

  private values(resource: TerraformResource): Record<string, unknown> {
    return this.asRecord((resource as unknown as Record<string, unknown>)?.['values']);
  }

  private asRecord(value: unknown): Record<string, unknown> {
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  }

  private asArray(value: unknown): unknown[] {
    if (Array.isArray(value)) return value;
    return value === undefined || value === null ? [] : [value];
  }
}
