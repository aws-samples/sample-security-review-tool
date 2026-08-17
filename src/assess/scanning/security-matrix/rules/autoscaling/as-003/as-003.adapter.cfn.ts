import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { As003Adapter } from './as-003.adapter.js';
import { isRecognizedScalingEvent, TEST_NOTIFICATION } from './as-003.events.js';

export class As003CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::AutoScaling::AutoScalingGroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): As003CfnAdapter {
    return new As003CfnAdapter(context);
  }
}

class As003CfnAdapter implements As003Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  isAutoScalingGroup(): boolean {
    return this.resourceType === 'AWS::AutoScaling::AutoScalingGroup';
  }

  hasNotificationConfiguration(): boolean {
    const configurations = this.configurations();
    if (Array.isArray(configurations)) return configurations.length > 0;
    return this.isDefined(configurations);
  }

  hasEmptyDestinationTopic(): boolean {
    const configurations = this.configurations();
    if (!Array.isArray(configurations)) return false;
    return configurations.some(configuration => this.namesNoTopic(configuration));
  }

  deliversScalingEvents(): boolean {
    const configurations = this.configurations();
    if (!Array.isArray(configurations)) return true;
    return configurations.some(configuration => this.deliversRealEvent(configuration));
  }

  listsNoEventTypes(): boolean {
    const configurations = this.configurations();
    if (!Array.isArray(configurations)) return false;
    return configurations.some(configuration => this.hasEmptyEventTypeList(configuration));
  }

  listsUnrecognizedEventType(): boolean {
    const configurations = this.configurations();
    if (!Array.isArray(configurations)) return false;
    return configurations.some(configuration => this.hasUnrecognizedEventType(configuration));
  }

  private namesNoTopic(configuration: unknown): boolean {
    if (!this.isRecord(configuration)) return false;
    const topic = this.topic(configuration);
    if (!this.isDefined(topic)) return true;
    return typeof topic === 'string' && topic.trim().length === 0;
  }

  private topic(configuration: unknown): unknown {
    return this.field(configuration, 'TopicARN');
  }

  private hasUnrecognizedEventType(configuration: unknown): boolean {
    const types = this.notificationTypes(configuration);
    if (!Array.isArray(types)) return false;
    return types.some(type => this.isUnrecognizedEvent(type));
  }

  private isUnrecognizedEvent(type: unknown): boolean {
    if (typeof type !== 'string') return false;
    if (type === TEST_NOTIFICATION) return false;
    return !isRecognizedScalingEvent(type);
  }

  private hasEmptyEventTypeList(configuration: unknown): boolean {
    const types = this.notificationTypes(configuration);
    if (!this.isDefined(types)) return true;
    return Array.isArray(types) && types.length === 0;
  }

  private deliversRealEvent(configuration: unknown): boolean {
    const types = this.notificationTypes(configuration);
    if (!this.isDefined(types)) return false;
    if (!Array.isArray(types)) return true;
    return types.some(type => this.isRealEvent(type));
  }

  private isRealEvent(type: unknown): boolean {
    if (typeof type !== 'string') return true;
    return isRecognizedScalingEvent(type);
  }

  private notificationTypes(configuration: unknown): unknown {
    return this.field(configuration, 'NotificationTypes');
  }

  private field(configuration: unknown, name: string): unknown {
    if (!this.isRecord(configuration)) return undefined;
    return (configuration as Record<string, unknown>)[name];
  }

  private isRecord(value: unknown): boolean {
    return typeof value === 'object' && value !== null && !this.isIntrinsic(value);
  }

  /** An unresolved intrinsic hides the whole configuration, so nothing can be asserted about it. */
  private isIntrinsic(value: unknown): boolean {
    if (typeof value !== 'object' || value === null) return false;
    return Object.keys(value as Record<string, unknown>).some(key => key.startsWith('Fn::') || key === 'Ref');
  }

  private configurations(): unknown {
    return this.properties()['NotificationConfigurations'];
  }

  private properties(): Record<string, unknown> {
    return (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
  }

  private isDefined(value: unknown): boolean {
    return value !== undefined && value !== null;
  }
}
