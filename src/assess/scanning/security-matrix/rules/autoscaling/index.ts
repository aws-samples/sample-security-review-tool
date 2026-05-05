export { default as AS001Rule } from './001-cooldown-periods.cf.js';
export { default as AS002Rule } from './002-health-checks.cf.js';
export { default as AS003Rule } from './003-email-notifications.cf.js';
export { default as AS004Rule } from './004-load-balancer-integration.cf.js';
export { default as AS005Rule } from './005-iam-roles-launch-templates.cf.js';
export { default as AS006Rule } from './006-multiple-availability-zones.cf.js';
import tfRule001 from './001-cooldown-periods.tf.js';
import tfRule002 from './002-health-checks.tf.js';
import tfRule003 from './003-email-notifications.tf.js';
import tfRule004 from './004-load-balancer-integration.tf.js';
import tfRule005 from './005-iam-roles-launch-templates.tf.js';
import tfRule006 from './006-multiple-availability-zones.tf.js';

export const tfAutoscalingRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
];
