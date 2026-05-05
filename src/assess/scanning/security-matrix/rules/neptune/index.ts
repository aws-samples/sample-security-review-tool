import neptune001 from './001-multi-az-configuration.cf.js';
import neptune002 from './002-auto-minor-version-upgrade.cf.js';
import neptune003 from './003-backup-retention-period.cf.js';
import neptune004 from './004-resource-tagging.cf.js';
import neptune005 from './005-restrict-ingress.cf.js';

export const neptuneRules = [
  neptune001,
  neptune002,
  neptune003,
  neptune004,
  neptune005
];

import tfRule001 from './001-multi-az-configuration.tf.js';
import tfRule002 from './002-auto-minor-version-upgrade.tf.js';
import tfRule003 from './003-backup-retention-period.tf.js';
import tfRule004 from './004-resource-tagging.tf.js';
import tfRule005 from './005-restrict-ingress.tf.js';

export const tfNeptuneRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
];
