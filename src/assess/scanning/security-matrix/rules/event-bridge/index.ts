import rule003 from './003-eventbus-policy-restriction.cf.js';
import rule004 from './004-eventbridge-archive-retention.cf.js';

import tfRule003 from './003-eventbus-policy-restriction.tf.js';
import tfRule004 from './004-eventbridge-archive-retention.tf.js';

export const eventBridgeRules = [
  rule003,
  rule004
];

export const tfEventBridgeRules = [
  tfRule003,
  tfRule004
];
