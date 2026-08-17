import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { As003Adapter } from './as-003.adapter.js';

const MISSING_NOTIFICATION_CONFIGURATION = 'missing-notification-configuration';
const TEST_NOTIFICATION_ONLY = 'test-notification-only';
const EMPTY_EVENT_TYPE_LIST = 'empty-event-type-list';
const UNRECOGNIZED_EVENT_TYPE = 'unrecognized-event-type';
const EMPTY_DESTINATION_TOPIC = 'empty-destination-topic';

const FINDINGS = {
  [MISSING_NOTIFICATION_CONFIGURATION]: {
    issue: 'Auto Scaling group has no notification configuration, so no launch, terminate, or failure scaling events are published to a notification topic.',
    remediation: 'Configure the Auto Scaling group to publish scaling event notifications to a notification topic, covering instance launch, instance terminate, and their corresponding failure events.',
  },
  [TEST_NOTIFICATION_ONLY]: {
    issue: 'Auto Scaling group notification configuration covers only the test notification, so no launch, terminate, or failure scaling event is ever delivered.',
    remediation: 'Extend the Auto Scaling group notification configuration so that it publishes real scaling events - instance launch, instance terminate, and their corresponding failure events - instead of only the test notification.',
  },
  [EMPTY_EVENT_TYPE_LIST]: {
    issue: 'Auto Scaling group notification configuration lists no scaling event types, so no launch, terminate, or failure scaling event is ever delivered.',
    remediation: 'List the scaling event types on the Auto Scaling group notification configuration - instance launch, instance terminate, and their corresponding failure events - so that the notification topic actually receives scaling events.',
  },
  [UNRECOGNIZED_EVENT_TYPE]: {
    issue: 'Auto Scaling group notification configuration lists only event types that Auto Scaling does not recognize, so no launch, terminate, or failure scaling event is ever delivered.',
    remediation: 'Replace the unrecognized event type on the Auto Scaling group notification configuration with the documented scaling event types - instance launch, instance terminate, and their corresponding failure events - so that the notification topic actually receives scaling events.',
  },
  [EMPTY_DESTINATION_TOPIC]: {
    issue: 'Auto Scaling group notification configuration names no destination topic, so no launch, terminate, or failure scaling event can be delivered.',
    remediation: 'Point the Auto Scaling group notification configuration at an existing notification topic so that the scaling event notifications have a real destination to be published to.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class As003Control extends SecurityControl<As003Adapter, FindingKey> {
  constructor() {
    super({
      id: 'AS-003',
      priority: 'HIGH',
      description: 'Auto Scaling Groups must have notification configurations set up to send scaling event notifications (e.g., to an SNS topic) for launch, terminate, or failure events.',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: As003Adapter): FindingKey | null {
    if (!adapter.isAutoScalingGroup()) return null;
    if (!adapter.hasNotificationConfiguration()) return MISSING_NOTIFICATION_CONFIGURATION;
    if (adapter.hasEmptyDestinationTopic()) return EMPTY_DESTINATION_TOPIC;
    if (adapter.deliversScalingEvents()) return null;
    if (adapter.listsNoEventTypes()) return EMPTY_EVENT_TYPE_LIST;
    if (adapter.listsUnrecognizedEventType()) return UNRECOGNIZED_EVENT_TYPE;
    return TEST_NOTIFICATION_ONLY;
  }
}

export const as003Control = new As003Control();
