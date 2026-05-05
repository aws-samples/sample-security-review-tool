import rule001 from './001-multi-az.cf.js';
import rule002 from './002-security-group-least-privilege.cf.js';
import rule003 from './003-minor-version-upgrade.cf.js';

export const dmsRules = [
  rule001,
  rule002,
  rule003
];
import tfRule001 from './001-multi-az.tf.js';
import tfRule002 from './002-security-group-least-privilege.tf.js';
import tfRule003 from './003-minor-version-upgrade.tf.js';

export const tfDmsRules = [
  tfRule001,
  tfRule002,
  tfRule003,
];
