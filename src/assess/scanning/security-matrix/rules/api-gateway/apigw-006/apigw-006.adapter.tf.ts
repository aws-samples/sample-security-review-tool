import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Apigw006Adapter } from './apigw-006.adapter.js';

const METHOD_SETTINGS_TYPE = 'aws_api_gateway_method_settings';
const STAGE_TYPE = 'aws_api_gateway_stage';
const ACCEPTED_LOGGING_LEVELS = ['INFO', 'ERROR'];
const DISABLED_LOGGING_LEVEL = 'OFF';
const CATCH_ALL_METHOD_PATHS = ['*/*', '*'];

export class Apigw006TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [STAGE_TYPE, METHOD_SETTINGS_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Apigw006TfAdapter {
    return new Apigw006TfAdapter(context);
  }
}

class Apigw006TfAdapter implements Apigw006Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasMethodLoggingConfiguration(): boolean {
    if (!this.isStage()) return true;
    return this.coveringMethodSettings().length > 0;
  }

  hasCatchAllCoverage(): boolean {
    if (!this.isStage()) return true;
    return this.catchAllMethodSettings().length > 0;
  }

  hasAcceptedLoggingLevel(): boolean {
    if (!this.isStage()) return true;
    return this.catchAllMethodSettings().some(resource => this.hasAcceptedLevel(resource));
  }

  hasLoggingDisabledForSomeMethod(): boolean {
    if (!this.isStage()) return false;
    return this.coveringMethodSettings().some(resource => this.hasDisabledLevel(resource));
  }

  private isStage(): boolean {
    return this.resourceType === STAGE_TYPE;
  }

  private catchAllMethodSettings(): TerraformResource[] {
    return this.coveringMethodSettings().filter(resource => this.isCatchAll(resource));
  }

  private coveringMethodSettings(): TerraformResource[] {
    return this.ctx.allResources.filter(resource => this.coversStage(resource));
  }

  private coversStage(resource: TerraformResource): boolean {
    if (resource.type !== METHOD_SETTINGS_TYPE) return false;
    const stageName = this.values(resource)['stage_name'];
    if (typeof stageName !== 'string') return true;
    if (stageName === this.ctx.resource.address) return true;
    return stageName === this.stageName() && this.targetsSameApi(resource);
  }

  private targetsSameApi(resource: TerraformResource): boolean {
    const settingsApi = this.values(resource)['rest_api_id'];
    const stageApi = this.values(this.ctx.resource)['rest_api_id'];
    if (typeof settingsApi !== 'string' || typeof stageApi !== 'string') return true;
    return settingsApi === stageApi;
  }

  private isCatchAll(resource: TerraformResource): boolean {
    const methodPath = this.values(resource)['method_path'];
    if (typeof methodPath !== 'string') return true;
    return CATCH_ALL_METHOD_PATHS.includes(methodPath);
  }

  private hasAcceptedLevel(resource: TerraformResource): boolean {
    const settings = this.values(resource)['settings'];
    if (!Array.isArray(settings)) return true;
    return settings.some(setting => this.isAccepted(this.loggingLevelOf(setting)));
  }

  private hasDisabledLevel(resource: TerraformResource): boolean {
    const settings = this.values(resource)['settings'];
    if (!Array.isArray(settings)) return false;
    return settings.some(setting => this.isDisabled(this.loggingLevelOf(setting)));
  }

  private loggingLevelOf(setting: unknown): unknown {
    if (typeof setting !== 'object' || setting === null) return undefined;
    return (setting as Record<string, unknown>)['logging_level'];
  }

  private isAccepted(loggingLevel: unknown): boolean {
    if (loggingLevel === null || loggingLevel === undefined) return true;
    return typeof loggingLevel === 'string' && ACCEPTED_LOGGING_LEVELS.includes(loggingLevel.toUpperCase());
  }

  private isDisabled(loggingLevel: unknown): boolean {
    return typeof loggingLevel === 'string' && loggingLevel.toUpperCase() === DISABLED_LOGGING_LEVEL;
  }

  private stageName(): unknown {
    return this.values(this.ctx.resource)['stage_name'];
  }

  private values(resource: TerraformResource): Record<string, unknown> {
    return (resource.values ?? {}) as Record<string, unknown>;
  }
}
