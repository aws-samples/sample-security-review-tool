import MEDIALIVE002 from './002-specific-iam-roles.cf.js';
import MEDIALIVE003 from './003-security-group-restrictions.cf.js';

export { MEDIALIVE002, MEDIALIVE003 };

export const medialiveRules = [
  MEDIALIVE002,
  MEDIALIVE003,
];
import tfRule001 from './002-specific-iam-roles.tf.js';
import tfRule002 from './003-security-group-restrictions.tf.js';

export const tfMedialiveRules = [
  tfRule001,
  tfRule002,
];
