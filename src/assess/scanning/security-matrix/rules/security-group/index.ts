import rule002 from './002-limit-egress.cf.js';

// Export rules array
export const securityGroupRules = [
  rule002,
];

import tfRule001 from './002-limit-egress.tf.js';

export const tfSecurityGroupRules = [
  tfRule001,
];
