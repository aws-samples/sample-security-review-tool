import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Apigw004Adapter } from './apigw-004.adapter.js';

const AUTHORIZED_TYPES = ['AWS_IAM', 'COGNITO_USER_POOLS', 'CUSTOM', 'JWT'];
/** Types that only provide authorization when an authorizer is associated with the method. */
const AUTHORIZER_BACKED_TYPES = ['COGNITO_USER_POOLS', 'CUSTOM', 'JWT'];

interface ApiFamily {
  readonly authorizerType: string;
  readonly apiIdProperty: string;
}

const ROUTE_TYPE = 'AWS::ApiGatewayV2::Route';
const API_TYPE = 'AWS::ApiGatewayV2::Api';
const WEBSOCKET_PROTOCOL = 'WEBSOCKET';
const CONNECT_ROUTE_KEY = '$connect';

const API_FAMILIES: Record<string, ApiFamily> = {
  'AWS::ApiGateway::Method': { authorizerType: 'AWS::ApiGateway::Authorizer', apiIdProperty: 'RestApiId' },
  [ROUTE_TYPE]: { authorizerType: 'AWS::ApiGatewayV2::Authorizer', apiIdProperty: 'ApiId' },
};

export class Apigw004CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::ApiGateway::Method', 'AWS::ApiGatewayV2::Route'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Apigw004CfnAdapter {
    return new Apigw004CfnAdapter(context);
  }
}

class Apigw004CfnAdapter implements Apigw004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  isOptionsMethod(): boolean {
    return this.httpMethod() === 'OPTIONS';
  }

  isWebSocketRouteWithoutAuthorizationSupport(): boolean {
    if (this.resourceType !== ROUTE_TYPE) return false;
    const routeKey = this.properties()['RouteKey'];
    if (routeKey === CONNECT_ROUTE_KEY) return false;
    return this.protocolTypeOfApi() === WEBSOCKET_PROTOCOL;
  }

  /** Undefined unless the route's API is in this template and states its protocol. */
  private protocolTypeOfApi(): string | undefined {
    const apiId = this.properties()['ApiId'];
    if (typeof apiId !== 'string') return undefined;
    const api = (this.ctx.template.Resources ?? {})[apiId] as Resource | undefined;
    if (api?.Type !== API_TYPE) return undefined;
    const protocolType = (api.Properties as Record<string, unknown> | undefined)?.['ProtocolType'];
    return typeof protocolType === 'string' ? protocolType.toUpperCase() : undefined;
  }

  hasNoAuthorizationConfiguration(): boolean {
    const authorizationType = this.properties()['AuthorizationType'];
    if (typeof authorizationType === 'string') {
      const type = authorizationType.toUpperCase();
      if (!AUTHORIZED_TYPES.includes(type)) return true;
      return AUTHORIZER_BACKED_TYPES.includes(type) && !this.hasAuthorizerReference();
    }
    if (authorizationType !== undefined) return false; // unresolved intrinsic — unknown
    return !this.hasAuthorizerReference();
  }

  private hasAuthorizerReference(): boolean {
    const authorizerId = this.properties()['AuthorizerId'];
    if (authorizerId === undefined || authorizerId === null || authorizerId === '') return false;
    return this.authorizerCoversThisApi(authorizerId);
  }

  /** Unknown wiring is treated as covered; only a provable mismatch of APIs is rejected. */
  private authorizerCoversThisApi(authorizerId: unknown): boolean {
    const family = API_FAMILIES[this.resourceType];
    if (!family || typeof authorizerId !== 'string') return true;
    const authorizer = this.findAuthorizer(authorizerId, family.authorizerType);
    if (!authorizer) return true;
    const authorizerApi = this.apiIdOf(authorizer.Properties, family.apiIdProperty);
    const methodApi = this.apiIdOf(this.properties(), family.apiIdProperty);
    if (authorizerApi === undefined || methodApi === undefined) return true;
    return authorizerApi === methodApi;
  }

  private findAuthorizer(logicalId: string, authorizerType: string): Resource | undefined {
    const resources = (this.ctx.template.Resources ?? {}) as Record<string, Resource>;
    const candidate = resources[logicalId];
    return candidate?.Type === authorizerType ? candidate : undefined;
  }

  private apiIdOf(properties: unknown, apiIdProperty: string): string | undefined {
    const value = ((properties ?? {}) as Record<string, unknown>)[apiIdProperty];
    return typeof value === 'string' ? value : undefined;
  }

  private httpMethod(): string | undefined {
    const properties = this.properties();
    const httpMethod = properties['HttpMethod'];
    if (typeof httpMethod === 'string') return httpMethod.toUpperCase();
    const routeKey = properties['RouteKey'];
    if (typeof routeKey === 'string') return routeKey.trim().split(/\s+/)[0]?.toUpperCase();
    return undefined;
  }

  private properties(): Record<string, unknown> {
    return (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
  }
}
