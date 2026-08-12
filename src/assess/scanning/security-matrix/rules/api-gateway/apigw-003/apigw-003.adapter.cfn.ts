import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Apigw003Adapter } from './apigw-003.adapter.js';

const CURRENT_ASSOCIATION_TYPE = 'AWS::WAFv2::WebACLAssociation';
const LEGACY_ASSOCIATION_TYPE = 'AWS::WAFRegional::WebACLAssociation';
const NEWER_GENERATION_API_TYPE = 'AWS::ApiGatewayV2::Api';
const STAGE_ARN_PATTERN = /\/restapis\/([^/]+)\/stages\/([^/]+)$/;
const ALL_STAGES = '*';

export class Apigw003CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::ApiGateway::Stage'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Apigw003CfnAdapter {
    return new Apigw003CfnAdapter(context);
  }
}

class Apigw003CfnAdapter implements Apigw003Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasWebAclAssociation(): boolean {
    return this.coversStage(CURRENT_ASSOCIATION_TYPE);
  }

  hasLegacyWebAclAssociationOnly(): boolean {
    return !this.hasWebAclAssociation() && this.coversStage(LEGACY_ASSOCIATION_TYPE);
  }

  belongsToNewerGenerationApi(): boolean {
    return this.referencedApi()?.Type === NEWER_GENERATION_API_TYPE;
  }

  private referencedApi(): Resource | undefined {
    const restApiId = this.stageProperties()['RestApiId'];
    if (typeof restApiId !== 'string') return undefined;
    return this.templateResources()[restApiId];
  }

  private coversStage(associationType: string): boolean {
    return this.associations(associationType).some(association => this.targetsStage(association));
  }

  private associations(associationType: string): Resource[] {
    return Object.values(this.templateResources()).filter(resource => resource?.Type === associationType);
  }

  private templateResources(): Record<string, Resource> {
    return (this.ctx.template.Resources ?? {}) as Record<string, Resource>;
  }

  private targetsStage(association: Resource): boolean {
    const properties = association.Properties as Record<string, unknown> | undefined;
    if (!this.namesWebAcl(properties)) return false;
    const resourceArn = properties?.['ResourceArn'];
    if (typeof resourceArn !== 'string') return true; // unresolved intrinsic: treat as unknown
    return this.arnIdentifiesStage(resourceArn);
  }

  private namesWebAcl(properties: Record<string, unknown> | undefined): boolean {
    const webAcl = this.firstDefined(properties?.['WebACLArn'], properties?.['WebACLId']);
    if (webAcl === undefined || webAcl === null) return false;
    if (typeof webAcl === 'string') return webAcl.trim() !== '';
    return true;
  }

  private firstDefined(...candidates: unknown[]): unknown {
    return candidates.find(candidate => candidate !== undefined && candidate !== null);
  }

  private arnIdentifiesStage(resourceArn: string): boolean {
    if (resourceArn === this.resourceId) return true;
    const match = STAGE_ARN_PATTERN.exec(resourceArn);
    if (!match) return resourceArn.includes(this.resourceId);
    const [, apiId, stageName] = match;
    if (stageName === ALL_STAGES) return this.matchesApi(apiId);
    return this.matchesApi(apiId) && this.identifiesThisStage(stageName);
  }

  private identifiesThisStage(stageSegment: string): boolean {
    return stageSegment === this.stageName() || stageSegment === this.resourceId;
  }

  private matchesApi(apiId: string): boolean {
    const restApiId = this.stageProperties()['RestApiId'];
    return typeof restApiId !== 'string' || restApiId === apiId;
  }

  private stageName(): string {
    const stageName = this.stageProperties()['StageName'];
    return typeof stageName === 'string' ? stageName : this.resourceId;
  }

  private stageProperties(): Record<string, unknown> {
    return (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
  }
}
