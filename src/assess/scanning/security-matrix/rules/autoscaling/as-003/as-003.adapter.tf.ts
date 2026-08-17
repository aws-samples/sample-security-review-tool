import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { isUnresolved } from '../../../terraform-rule-base.js';
import { As003Adapter } from './as-003.adapter.js';
import { isRecognizedScalingEvent, TEST_NOTIFICATION } from './as-003.events.js';

const NOTIFICATION_TYPE = 'aws_autoscaling_notification';

export class As003TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_autoscaling_group', NOTIFICATION_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): As003TfAdapter {
    return new As003TfAdapter(context);
  }
}

class As003TfAdapter implements As003Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  isAutoScalingGroup(): boolean {
    return this.resourceType === 'aws_autoscaling_group';
  }

  hasNotificationConfiguration(): boolean {
    return this.coveringNotifications().length > 0 || this.hasAmbiguousCoverage();
  }

  hasEmptyDestinationTopic(): boolean {
    if (this.hasAmbiguousCoverage()) return false;
    return this.coveringNotifications().some(notification => this.namesNoTopic(notification));
  }

  deliversScalingEvents(): boolean {
    if (this.hasAmbiguousCoverage()) return true;
    return this.coveringNotifications().some(notification => this.deliversRealEvent(notification));
  }

  listsNoEventTypes(): boolean {
    if (this.hasAmbiguousCoverage()) return false;
    return this.coveringNotifications().some(notification => this.hasEmptyEventTypeList(notification));
  }

  listsUnrecognizedEventType(): boolean {
    if (this.hasAmbiguousCoverage()) return false;
    return this.coveringNotifications().some(notification => this.hasUnrecognizedEventType(notification));
  }

  private namesNoTopic(notification: TerraformResource): boolean {
    const topic = (notification.values as Record<string, unknown>)?.['topic_arn'];
    if (!this.isDefined(topic)) return true;
    if (this.isUnknown(topic)) return false;
    return typeof topic === 'string' && topic.trim().length === 0;
  }

  private hasUnrecognizedEventType(notification: TerraformResource): boolean {
    const events = this.events(notification);
    const list = Array.isArray(events) ? events : [events];
    return list.some(event => this.isUnrecognizedEvent(event));
  }

  private isUnrecognizedEvent(event: unknown): boolean {
    if (typeof event !== 'string') return false;
    if (isUnresolved(event)) return false;
    if (event === TEST_NOTIFICATION) return false;
    return !isRecognizedScalingEvent(event);
  }

  private hasEmptyEventTypeList(notification: TerraformResource): boolean {
    const events = this.events(notification);
    if (!this.isDefined(events)) return true;
    return Array.isArray(events) && events.length === 0;
  }

  private deliversRealEvent(notification: TerraformResource): boolean {
    const events = this.events(notification);
    if (!this.isDefined(events)) return false;
    if (!Array.isArray(events)) return this.isRealEvent(events);
    return events.some(event => this.isRealEvent(event));
  }

  private events(notification: TerraformResource): unknown {
    return (notification.values as Record<string, unknown>)?.['notifications'];
  }

  private isRealEvent(event: unknown): boolean {
    if (typeof event !== 'string') return true;
    if (isUnresolved(event)) return true;
    return isRecognizedScalingEvent(event);
  }

  private isDefined(value: unknown): boolean {
    return value !== undefined && value !== null;
  }

  private notifications(): TerraformResource[] {
    return this.ctx.allResources.filter(resource => resource.type === NOTIFICATION_TYPE);
  }

  /** Notifications that provably cover this group. */
  private coveringNotifications(): TerraformResource[] {
    return this.notifications().filter(notification => this.coversGroup(notification));
  }

  /** True when a notification's target group cannot be resolved, so coverage is unknowable. */
  private hasAmbiguousCoverage(): boolean {
    return this.notifications().some(notification => this.mayCoverGroup(notification));
  }

  private mayCoverGroup(notification: TerraformResource): boolean {
    const groupNames = this.groupNames(notification);
    if (this.isUnknown(groupNames)) return true;
    if (!Array.isArray(groupNames)) return false;
    return groupNames.some(name => this.isUnknown(name));
  }

  private coversGroup(notification: TerraformResource): boolean {
    const groupNames = this.groupNames(notification);
    if (!Array.isArray(groupNames)) return false;
    return groupNames.some(name => this.matchesGroup(name));
  }

  private groupNames(notification: TerraformResource): unknown {
    return (notification.values as Record<string, unknown>)?.['group_names'];
  }

  private matchesGroup(name: unknown): boolean {
    if (typeof name !== 'string') return false;
    if (this.isUnknown(name)) return false;
    if (name === this.ctx.resource.address) return true;
    const literalName = (this.ctx.resource.values as Record<string, unknown>)?.['name'];
    return typeof literalName === 'string' && name === literalName;
  }

  private isUnknown(value: unknown): boolean {
    return typeof value === 'string' && isUnresolved(value);
  }
}
