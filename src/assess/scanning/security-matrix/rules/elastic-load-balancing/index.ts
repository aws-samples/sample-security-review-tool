import elb001 from './001-alb-for-http-https.cf.js';
import elb002 from './002-access-logs-enabled.cf.js';
import elb003 from './003-connection-draining.cf.js';
import elb004 from './004-multi-az-cross-zone.cf.js';
import elb005 from './005-secure-protocols.cf.js';
import elb006 from './006-secure-security-groups.cf.js';

export const elbRules = [
  elb001,
  elb002,
  elb003,
  elb004,
  elb005,
  elb006,
];
import tfRule001 from './001-alb-for-http-https.tf.js';
import tfRule002 from './002-access-logs-enabled.tf.js';
import tfRule003 from './003-connection-draining.tf.js';
import tfRule004 from './004-multi-az-cross-zone.tf.js';
import tfRule005 from './005-secure-protocols.tf.js';
import tfRule006 from './006-secure-security-groups.tf.js';

export const tfElbRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
];
