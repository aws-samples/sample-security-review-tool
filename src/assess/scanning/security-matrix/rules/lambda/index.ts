import rule002 from './002-secrets-manager.js';
import rule003 from './003-timeout-memory.js';
import rule004 from './004-xray-tracing.js';
import rule005 from './005-least-privilege-roles.js';
import rule011 from './011-cloudwatch-alarms.js';
import rule012 from './012-unique-execution-role.js';
import rule015 from './015-container-image-repository.js';

export const lambdaRules = [
  rule002,
  rule003,
  rule004,
  rule005,
  rule011,
  rule012,
  rule015
];
