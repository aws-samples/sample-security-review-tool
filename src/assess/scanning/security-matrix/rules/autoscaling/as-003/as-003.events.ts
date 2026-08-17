/** Auto Scaling test-only notification - documented as distinct from real scaling events. */
export const TEST_NOTIFICATION = 'autoscaling:TEST_NOTIFICATION';

/** The launch, terminate, and failure events that constitute real scaling notifications. */
const SCALING_EVENTS = [
  'autoscaling:EC2_INSTANCE_LAUNCH',
  'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
  'autoscaling:EC2_INSTANCE_TERMINATE',
  'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
];

/** True when the event type is exactly one of the documented launch, terminate, or failure events. */
export function isRecognizedScalingEvent(eventType: string): boolean {
  return SCALING_EVENTS.includes(eventType.trim());
}
