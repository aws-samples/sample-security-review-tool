import elb001 from './001-alb-for-http-https.js';
import elb002 from './002-access-logs-enabled.js';
import elb003 from './003-connection-draining.js';
import elb004 from './004-multi-az-cross-zone.js';
import elb005 from './005-secure-protocols.js';
import elb006 from './006-secure-security-groups.js';

export const elbRules = [
  elb001,
  elb002,
  elb003,
  elb004,
  elb005,
  elb006,
];