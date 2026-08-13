import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Apigw006Adapter } from './apigw-006.adapter.js';

const ACCEPTED_LOGGING_LEVELS = ['INFO', 'ERROR'];
const DISABLED_LOGGING_LEVEL = 'OFF';
const CATCH_ALL_HTTP_METHOD = '*';
const CATCH_ALL_RESOURCE_PATHS = ['/*', '*', '*/*'];

export class Apigw006CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::ApiGateway::Stage'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Apigw006CfnAdapter {
    return new Apigw006CfnAdapter(context);
  }
}

class Apigw006CfnAdapter implements Apigw006Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasMethodLoggingConfiguration(): boolean {
    const methodSettings = this.methodSettings();
    if (!Array.isArray(methodSettings)) return this.isUnresolved(methodSettings);
    return methodSettings.length > 0;
  }

  hasCatchAllCoverage(): boolean {
    const methodSettings = this.methodSettings();
    if (!Array.isArray(methodSettings)) return true;
    return methodSettings.some(setting => this.isCatchAll(setting));
  }

  hasAcceptedLoggingLevel(): boolean {
    const methodSettings = this.methodSettings();
    if (!Array.isArray(methodSettings)) return true;
    return methodSettings
      .filter(setting => this.isCatchAll(setting))
      .some(setting => this.isAccepted(this.valueOf(setting, 'LoggingLevel')));
  }

  hasLoggingDisabledForSomeMethod(): boolean {
    const methodSettings = this.methodSettings();
    if (!Array.isArray(methodSettings)) return false;
    return methodSettings.some(setting => this.isDisabled(this.valueOf(setting, 'LoggingLevel')));
  }

  private isCatchAll(setting: unknown): boolean {
    return this.isCatchAllHttpMethod(this.valueOf(setting, 'HttpMethod'))
      && this.isCatchAllResourcePath(this.valueOf(setting, 'ResourcePath'));
  }

  private isCatchAllHttpMethod(httpMethod: unknown): boolean {
    if (httpMethod === undefined || this.isUnresolved(httpMethod)) return true;
    return httpMethod === CATCH_ALL_HTTP_METHOD;
  }

  private isCatchAllResourcePath(resourcePath: unknown): boolean {
    if (resourcePath === undefined || this.isUnresolved(resourcePath)) return true;
    return typeof resourcePath === 'string' && CATCH_ALL_RESOURCE_PATHS.includes(resourcePath);
  }

  private valueOf(setting: unknown, key: string): unknown {
    if (typeof setting !== 'object' || setting === null) return undefined;
    return (setting as Record<string, unknown>)[key];
  }

  private isAccepted(loggingLevel: unknown): boolean {
    if (this.isUnresolved(loggingLevel)) return true;
    return typeof loggingLevel === 'string' && ACCEPTED_LOGGING_LEVELS.includes(loggingLevel.toUpperCase());
  }

  private isDisabled(loggingLevel: unknown): boolean {
    return typeof loggingLevel === 'string' && loggingLevel.toUpperCase() === DISABLED_LOGGING_LEVEL;
  }

  private methodSettings(): unknown {
    return this.properties()['MethodSettings'];
  }

  private properties(): Record<string, unknown> {
    return (this.ctx.resource.Properties ?? {}) as unknown as Record<string, unknown>;
  }

  private isUnresolved(value: unknown): boolean {
    return typeof value === 'object' && value !== null;
  }
}
