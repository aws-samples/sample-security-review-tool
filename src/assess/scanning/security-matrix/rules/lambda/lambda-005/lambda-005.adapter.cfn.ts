import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Lambda005Adapter } from './lambda-005.adapter.js';
import { hasWildcardActionAndResource, isBroadManagedPolicy, trustsLambdaServicePrincipal } from './lambda-005.policy.js';

const FUNCTION_TYPES = ['AWS::Lambda::Function', 'AWS::Serverless::Function'];

export class Lambda005CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::IAM::Role', 'AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'AWS::Lambda::Function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Lambda005CfnAdapter {
    return new Lambda005CfnAdapter(context);
  }
}

class Lambda005CfnAdapter implements Lambda005Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  isLambdaExecutionRole(): boolean {
    if (this.resourceType !== 'AWS::IAM::Role') return false;
    return this.trustsLambda() || this.isReferencedByFunction();
  }

  private trustsLambda(): boolean {
    return trustsLambdaServicePrincipal(this.properties(this.ctx.resource)['AssumeRolePolicyDocument']);
  }

  private isReferencedByFunction(): boolean {
    return FUNCTION_TYPES
      .flatMap(type => this.resourcesOfType(type))
      .some(([, resource]) => this.properties(resource)['Role'] === this.resourceId);
  }

  grantsWildcardActionOnAllResources(): boolean {
    return this.inlinePolicyDocuments().some(hasWildcardActionAndResource);
  }

  usesOverlyBroadManagedPolicy(): boolean {
    return this.managedPolicyReferences().some(isBroadManagedPolicy);
  }

  private inlinePolicyDocuments(): unknown[] {
    const embedded = this.asArray(this.properties(this.ctx.resource)['Policies'])
      .map(policy => this.asRecord(policy)['PolicyDocument']);
    const standalone = this.resourcesOfType('AWS::IAM::Policy')
      .filter(([, resource]) => this.targetsThisRole(resource))
      .map(([, resource]) => this.properties(resource)['PolicyDocument']);
    return [...embedded, ...standalone];
  }

  private managedPolicyReferences(): unknown[] {
    const attached = this.asArray(this.properties(this.ctx.resource)['ManagedPolicyArns']);
    const declared = this.resourcesOfType('AWS::IAM::ManagedPolicy')
      .filter(([, resource]) => this.targetsThisRole(resource))
      .map(([logicalId, resource]) => this.properties(resource)['ManagedPolicyName'] ?? logicalId);
    return [...attached, ...declared];
  }

  private targetsThisRole(resource: Resource): boolean {
    return this.asArray(this.properties(resource)['Roles']).includes(this.resourceId);
  }

  private resourcesOfType(type: string): [string, Resource][] {
    const resources = (this.ctx.template.Resources ?? {}) as Record<string, Resource>;
    return Object.entries(resources).filter(([, resource]) => resource?.Type === type);
  }

  private properties(resource: Resource): Record<string, unknown> {
    return this.asRecord((resource as unknown as Record<string, unknown>)?.['Properties']);
  }

  private asRecord(value: unknown): Record<string, unknown> {
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  }

  private asArray(value: unknown): unknown[] {
    if (Array.isArray(value)) return value;
    return value === undefined || value === null ? [] : [value];
  }
}
