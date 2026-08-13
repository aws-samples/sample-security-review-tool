import rule002 from './002-secrets-manager.cf.js';
import rule005 from './005-least-privilege-roles.cf.js';

export const lambdaRules = [
  rule002,
  rule005,
];

import tfRule001 from './002-secrets-manager.tf.js';
import tfRule004 from './005-least-privilege-roles.tf.js';

export const tfLambdaRules = [
  tfRule001,
  tfRule004,
];
