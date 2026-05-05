import rule002 from './002-secrets-manager.cf.js';
import rule003 from './003-timeout-memory.cf.js';
import rule004 from './004-xray-tracing.cf.js';
import rule005 from './005-least-privilege-roles.cf.js';
import rule011 from './011-cloudwatch-alarms.cf.js';
import rule012 from './012-unique-execution-role.cf.js';
import rule015 from './015-container-image-repository.cf.js';

export const lambdaRules = [
  rule002,
  rule003,
  rule004,
  rule005,
  rule011,
  rule012,
  rule015
];

import tfRule001 from './002-secrets-manager.tf.js';
import tfRule002 from './003-timeout-memory.tf.js';
import tfRule003 from './004-xray-tracing.tf.js';
import tfRule004 from './005-least-privilege-roles.tf.js';
import tfRule005 from './011-cloudwatch-alarms.tf.js';
import tfRule006 from './012-unique-execution-role.tf.js';
import tfRule007 from './013-secrets-in-env-vars.tf.js';
import tfRule008 from './015-container-image-repository.tf.js';
import tfRule009 from './016-container-image-scanning.tf.js';

export const tfLambdaRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
  tfRule007,
  tfRule008,
  tfRule009,
];
