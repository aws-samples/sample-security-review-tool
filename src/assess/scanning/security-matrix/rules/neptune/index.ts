import neptune001 from './001-multi-az-configuration.js';
import neptune002 from './002-auto-minor-version-upgrade.js';
import neptune003 from './003-backup-retention-period.js';
import neptune004 from './004-resource-tagging.js';
import neptune005 from './005-restrict-ingress.js';

export const neptuneRules = [
  neptune001,
  neptune002,
  neptune003,
  neptune004,
  neptune005
];
