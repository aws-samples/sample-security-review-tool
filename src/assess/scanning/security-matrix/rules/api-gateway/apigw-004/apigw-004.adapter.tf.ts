import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Apigw004Adapter } from './apigw-004.adapter.js';

const AUTHORIZED_TYPES = ['AWS_IAM', 'COGNITO_USER_POOLS', 'CUSTOM', 'JWT'];
/** Types that only provide authorization when an authorizer is associated with the method. */
const AUTHORIZER_BACKED_TYPES = ['COGNITO_USER_POOLS', 'CUSTOM', 'JWT'];

interface ApiFamily {
  readonly authorizerType: string;
  readonly apiIdArgument: string;
}

const API_FAMILIES: Record<string, ApiFamily> = {
  aws_api_gateway_method: { authorizerType: 'aws_api_gateway_authorizer', apiIdArgument: 'rest_api_id' },
  aws_apigatewayv2_route: { authorizerType: 'aws_apigatewayv2_authorizer', apiIdArgument: 'api_id' },
};

export class Apigw004TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_api_gateway_method', 'aws_apigatewayv2_route'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Apigw004TfAdapter {
    return new Apigw004TfAdapter(context);
  }
}

class Apigw004TfAdapter implements Apigw004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  isOptionsMethod(): boolean {
    return this.httpMethod() === 'OPTIONS';
  }

  hasNoAuthorizationConfiguration(): boolean {
    const authorization = this.declaredAuthorization();
    if (authorization === null) return false; // unresolved at plan time — unknown
    if (typeof authorization === 'string') {
      const type = authorization.toUpperCase();
      if (!AUTHORIZED_TYPES.includes(type)) return true;
      return AUTHORIZER_BACKED_TYPES.includes(type) && !this.hasAuthorizerReference();
    }
    return !this.hasAuthorizerReference();
  }

  /** The declared authorization argument, preserving null (unknown) from the plan. */
  private declaredAuthorization(): unknown {
    const values = this.values();
    const authorization = values['authorization'];
    return authorization !== undefined ? authorization : values['authorization_type'];
  }

  private hasAuthorizerReference(): boolean {
    const authorizerId = this.values()['authorizer_id'];
    if (typeof authorizerId !== 'string' || authorizerId.length === 0) return false;
    return this.authorizerCoversThisApi(authorizerId);
  }

  /** Unknown wiring is treated as covered; only a provable mismatch of APIs is rejected. */
  private authorizerCoversThisApi(authorizerId: string): boolean {
    const family = API_FAMILIES[this.resourceType];
    if (!family) return true;
    const authorizer = this.findAuthorizer(authorizerId, family.authorizerType);
    if (!authorizer) return true;
    const authorizerApi = this.apiIdOf(authorizer, family.apiIdArgument);
    const methodApi = this.apiIdOf(this.ctx.resource, family.apiIdArgument);
    if (authorizerApi === undefined || methodApi === undefined) return true;
    return authorizerApi === methodApi;
  }

  private findAuthorizer(reference: string, authorizerType: string): TerraformResource | undefined {
    return (this.ctx.allResources ?? []).find(
      resource =>
        resource.type === authorizerType &&
        (resource.address === reference || this.nameOf(resource) === reference),
    );
  }

  private nameOf(resource: TerraformResource): string | undefined {
    const name = (resource.values ?? {})['name'];
    return typeof name === 'string' ? name : undefined;
  }

  private apiIdOf(resource: TerraformResource, apiIdArgument: string): string | undefined {
    const value = ((resource.values ?? {}) as Record<string, unknown>)[apiIdArgument];
    return typeof value === 'string' ? value : undefined;
  }

  private httpMethod(): string | undefined {
    const httpMethod = this.values()['http_method'];
    if (typeof httpMethod === 'string') return httpMethod.toUpperCase();
    const routeKey = this.values()['route_key'];
    if (typeof routeKey === 'string') return routeKey.trim().split(/\s+/)[0]?.toUpperCase();
    return undefined;
  }

  private values(): Record<string, unknown> {
    return (this.ctx.resource.values ?? {}) as Record<string, unknown>;
  }
}
