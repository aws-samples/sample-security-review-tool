import KMS002Rule from './002-cmk-least-privilege.cf.js';
import KMS007Rule from './007-monitoring-configuration.cf.js';

export const kmsRules = [
  KMS002Rule,
  KMS007Rule,
];
import tfRule001 from './002-cmk-least-privilege.tf.js';
import tfRule002 from './007-monitoring-configuration.tf.js';

export const tfKmsRules = [
  tfRule001,
  tfRule002,
];
