import { ControlAdapter } from '../../../controls/types.js';

export interface As003Adapter extends ControlAdapter {
  /** True when the group is an Auto Scaling group that this control should evaluate. */
  isAutoScalingGroup(): boolean;

  /** True when a notification configuration covers this Auto Scaling group. */
  hasNotificationConfiguration(): boolean;

  /** True when a covering notification configuration delivers at least one real scaling event. */
  deliversScalingEvents(): boolean;

  /** True when a covering notification configuration lists no event types at all. */
  listsNoEventTypes(): boolean;

  /** True when a covering notification configuration lists an event type that Auto Scaling does not recognize. */
  listsUnrecognizedEventType(): boolean;

  /** True when a covering notification configuration names an empty destination topic. */
  hasEmptyDestinationTopic(): boolean;
}
