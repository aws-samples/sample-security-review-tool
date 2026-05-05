export { default as SSM001Rule } from './005-minimal-input-parameters.cf.js';
export { default as SSM002Rule } from './006-parameter-validation.cf.js';
export { default as SSM003Rule } from './007-non-sensitive-parameters.cf.js';
import tfRule001 from './005-minimal-input-parameters.tf.js';
import tfRule002 from './006-parameter-validation.tf.js';
import tfRule003 from './007-non-sensitive-parameters.tf.js';

export const tfSsmRules = [
  tfRule001,
  tfRule002,
  tfRule003,
];
