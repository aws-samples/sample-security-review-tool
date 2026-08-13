import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Apigw008Adapter, CachedMethodSetting, hasUnencryptedCaching } from './apigw-008.adapter.js';

const STAGE_TYPE = 'AWS::ApiGateway::Stage';
const DEPLOYMENT_TYPE = 'AWS::ApiGateway::Deployment';
const ANY_METHOD = '*';
const ANY_RESOURCE_PATHS = ['/*', '*'];

export class Apigw008CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = [STAGE_TYPE, DEPLOYMENT_TYPE, 'AWS::Serverless::Api'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Apigw008CfnAdapter {
    return new Apigw008CfnAdapter(context);
  }
}

class Apigw008CfnAdapter implements Apigw008Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasUnencryptedCachedMethod(): boolean {
    return hasUnencryptedCaching(this.methodSettings());
  }

  private methodSettings(): CachedMethodSetting[] {
    return [...this.ownSettings(this.ctx.resource), ...this.relatedDeploymentSettings()];
  }

  private ownSettings(resource: Resource): CachedMethodSetting[] {
    const properties = (resource.Properties ?? {}) as Record<string, unknown>;
    const stageDescription = (properties['StageDescription'] ?? {}) as Record<string, unknown>;
    return [
      ...this.toSettings(properties['MethodSettings']),
      ...this.toSettings((stageDescription as Record<string, unknown>)['MethodSettings']),
    ];
  }

  private relatedDeploymentSettings(): CachedMethodSetting[] {
    if (this.resourceType !== STAGE_TYPE) return [];
    return this.deploymentsTargetingStage().flatMap(deployment => this.ownSettings(deployment));
  }

  private deploymentsTargetingStage(): Resource[] {
    const resources = (this.ctx.template.Resources ?? {}) as Record<string, Resource>;
    return Object.entries(resources)
      .filter(([logicalId, resource]) => resource?.Type === DEPLOYMENT_TYPE && this.targetsStage(logicalId, resource))
      .map(([, resource]) => resource);
  }

  private targetsStage(logicalId: string, deployment: Resource): boolean {
    const stage = (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
    const properties = (deployment.Properties ?? {}) as Record<string, unknown>;
    if (stage['DeploymentId'] === logicalId) return true;
    return (
      this.sameScalar(stage['StageName'], properties['StageName']) &&
      this.sameScalar(stage['RestApiId'], properties['RestApiId'])
    );
  }

  private sameScalar(left: unknown, right: unknown): boolean {
    return typeof left === 'string' && typeof right === 'string' && left === right;
  }

  private toSettings(value: unknown): CachedMethodSetting[] {
    if (!Array.isArray(value)) return [];
    return value
      .filter((entry): entry is Record<string, unknown> => typeof entry === 'object' && entry !== null)
      .map(entry => ({
        cachingEnabled: entry['CachingEnabled'],
        cacheDataEncrypted: entry['CacheDataEncrypted'],
        isCatchAll: this.isCatchAll(entry),
      }));
  }

  private isCatchAll(entry: Record<string, unknown>): boolean {
    const resourcePath = entry['ResourcePath'];
    return (
      entry['HttpMethod'] === ANY_METHOD &&
      typeof resourcePath === 'string' &&
      ANY_RESOURCE_PATHS.includes(resourcePath)
    );
  }
}
