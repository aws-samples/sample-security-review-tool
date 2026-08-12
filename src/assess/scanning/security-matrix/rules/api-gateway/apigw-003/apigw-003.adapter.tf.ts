import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Apigw003Adapter } from './apigw-003.adapter.js';

const CURRENT_ASSOCIATION_TYPE = 'aws_wafv2_web_acl_association';
const LEGACY_ASSOCIATION_TYPE = 'aws_wafregional_web_acl_association';
const STAGE_TYPE = 'aws_api_gateway_stage';
const NEWER_GENERATION_API_TYPE = 'aws_apigatewayv2_api';
const STAGE_ARN_PATTERN = /\/restapis\/([^/]+)\/stages\/([^/]+)$/;
const ALL_STAGES = '*';

export class Apigw003TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [STAGE_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Apigw003TfAdapter {
    return new Apigw003TfAdapter(context);
  }
}

class Apigw003TfAdapter implements Apigw003Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasWebAclAssociation(): boolean {
    return this.coversStage(CURRENT_ASSOCIATION_TYPE);
  }

  hasLegacyWebAclAssociationOnly(): boolean {
    return !this.hasWebAclAssociation() && this.coversStage(LEGACY_ASSOCIATION_TYPE);
  }

  belongsToNewerGenerationApi(): boolean {
    const restApiId = this.restApiId();
    if (typeof restApiId !== 'string' || restApiId === '') return false;
    if (restApiId.startsWith(`${NEWER_GENERATION_API_TYPE}.`)) return true;
    return this.allResources().some(
      resource => resource?.type === NEWER_GENERATION_API_TYPE && resource.address === restApiId,
    );
  }

  private coversStage(associationType: string): boolean {
    return this.associations(associationType).some(association => this.protectsThisStage(association));
  }

  private associations(associationType: string): TerraformResource[] {
    return this.allResources().filter(resource => resource?.type === associationType);
  }

  private allResources(): TerraformResource[] {
    return this.ctx.allResources ?? [];
  }

  private protectsThisStage(association: TerraformResource): boolean {
    const values = (association.values ?? {}) as Record<string, unknown>;
    if (!this.namesWebAcl(values)) return false;
    const target = values['resource_arn'];
    if (typeof target !== 'string') return true; // unknown at plan time: do not flag
    return this.identifiesThisStage(target);
  }

  private namesWebAcl(values: Record<string, unknown>): boolean {
    const webAcl = this.firstDefined(values['web_acl_arn'], values['web_acl_id']);
    if (webAcl === undefined || webAcl === null) return false;
    if (typeof webAcl === 'string') return webAcl.trim() !== '';
    return true;
  }

  private firstDefined(...candidates: unknown[]): unknown {
    return candidates.find(candidate => candidate !== undefined && candidate !== null);
  }

  private identifiesThisStage(target: string): boolean {
    if (target === this.resourceId) return true;
    const match = STAGE_ARN_PATTERN.exec(target);
    if (!match) return target.includes(this.resourceId);
    const [, apiId, stageName] = match;
    // A wildcard stage segment covers every stage of the referenced API, so the
    // assessed stage is protected exactly when the API is the assessed stage's API.
    if (stageName === ALL_STAGES) return this.apiMatches(this.restApiId(), apiId);
    if (stageName !== this.stageName()) return false;
    if (this.apiMatches(this.restApiId(), apiId)) return true;
    return !this.anotherStageClaims(apiId, stageName);
  }

  /** True when a different stage in the plan is a better match for the protected API. */
  private anotherStageClaims(apiId: string, stageName: string): boolean {
    return this.allResources().some(resource => {
      if (resource?.type !== STAGE_TYPE || resource.address === this.resourceId) return false;
      const values = (resource.values ?? {}) as Record<string, unknown>;
      if (values['stage_name'] !== stageName) return false;
      return this.apiMatches(values['rest_api_id'], apiId);
    });
  }

  private apiMatches(restApiId: unknown, apiId: string): boolean {
    if (typeof restApiId !== 'string' || restApiId === '') return false;
    if (restApiId === apiId || restApiId.endsWith(`.${apiId}`) || apiId.includes(restApiId)) return true;
    const referencedName = restApiId.split('.').pop() ?? '';
    return referencedName !== '' && apiId.includes(referencedName);
  }

  private restApiId(): unknown {
    return this.stageValues()['rest_api_id'];
  }

  private stageName(): string {
    const stageName = this.stageValues()['stage_name'];
    return typeof stageName === 'string' ? stageName : this.resourceId;
  }

  private stageValues(): Record<string, unknown> {
    return (this.ctx.resource.values ?? {}) as Record<string, unknown>;
  }
}
