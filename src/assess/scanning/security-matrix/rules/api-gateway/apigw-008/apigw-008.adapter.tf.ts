import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Apigw008Adapter, CachedMethodSetting, hasUnencryptedCaching } from './apigw-008.adapter.js';

const METHOD_SETTINGS_TYPE = 'aws_api_gateway_method_settings';
const STAGE_TYPE = 'aws_api_gateway_stage';
const CATCH_ALL_METHOD_PATHS = ['*/*', '*'];

export class Apigw008TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [STAGE_TYPE, METHOD_SETTINGS_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Apigw008TfAdapter {
    return new Apigw008TfAdapter(context);
  }
}

class Apigw008TfAdapter implements Apigw008Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasUnencryptedCachedMethod(): boolean {
    return hasUnencryptedCaching(this.methodSettings());
  }

  private methodSettings(): CachedMethodSetting[] {
    if (this.resourceType === METHOD_SETTINGS_TYPE) {
      return [...this.settingsOf(this.ctx.resource), ...this.siblingCatchAllSettings()];
    }
    return this.settingsResourcesTargetingStage().flatMap(resource => this.settingsOf(resource));
  }

  /** Catch-all settings declared on another resource for the same stage still apply. */
  private siblingCatchAllSettings(): CachedMethodSetting[] {
    const own = this.ctx.resource;
    const stageName = this.valueOf(own, 'stage_name');
    if (typeof stageName !== 'string') return [];
    return (this.ctx.allResources ?? [])
      .filter(resource => resource.type === METHOD_SETTINGS_TYPE && resource.address !== own.address)
      .filter(resource => this.valueOf(resource, 'stage_name') === stageName)
      .flatMap(resource => this.settingsOf(resource))
      .filter(setting => setting.isCatchAll === true);
  }

  private settingsResourcesTargetingStage(): TerraformResource[] {
    const stage = this.ctx.resource;
    return (this.ctx.allResources ?? []).filter(
      resource => resource.type === METHOD_SETTINGS_TYPE && this.targetsStage(resource, stage),
    );
  }

  private targetsStage(settings: TerraformResource, stage: TerraformResource): boolean {
    const target = this.valueOf(settings, 'stage_name');
    if (typeof target !== 'string') return false;
    if (target === stage.address) return true;
    const literalName = this.valueOf(stage, 'stage_name');
    return typeof literalName === 'string' && target === literalName;
  }

  private valueOf(resource: TerraformResource, key: string): unknown {
    return (resource.values as Record<string, unknown> | undefined)?.[key];
  }

  private settingsOf(resource: TerraformResource): CachedMethodSetting[] {
    const raw = this.valueOf(resource, 'settings');
    const blocks = Array.isArray(raw) ? raw : [raw];
    const catchAll = this.isCatchAll(resource);
    return blocks
      .filter((block): block is Record<string, unknown> => typeof block === 'object' && block !== null)
      .map(block => ({
        cachingEnabled: block['caching_enabled'],
        cacheDataEncrypted: block['cache_data_encrypted'],
        isCatchAll: catchAll,
      }));
  }

  private isCatchAll(resource: TerraformResource): boolean {
    const methodPath = this.valueOf(resource, 'method_path');
    return typeof methodPath === 'string' && CATCH_ALL_METHOD_PATHS.includes(methodPath);
  }
}
