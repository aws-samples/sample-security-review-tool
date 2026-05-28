import rule002 from './002-secrets-manager.cf.js';
import rule005 from './005-least-privilege-roles.cf.js';
import rule015 from './015-container-image-repository.cf.js';

export const lambdaRules = [
  rule002,
  rule005,
  rule015
];

import tfRule001 from './002-secrets-manager.tf.js';
import tfRule004 from './005-least-privilege-roles.tf.js';
import tfRule007 from './013-secrets-in-env-vars.tf.js';
import tfRule008 from './015-container-image-repository.tf.js';
import tfRule009 from './016-container-image-scanning.tf.js';

export const tfLambdaRules = [
  tfRule001,
  tfRule004,
  tfRule007,
  tfRule008,
  tfRule009,
];
