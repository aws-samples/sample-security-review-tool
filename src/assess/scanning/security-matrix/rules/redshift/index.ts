import redshift001 from './001-ssl-parameter-groups.cf.js';
import redshift002 from './002-default-master-username.cf.js';
import redshift003 from './003-audit-logging.cf.js';
import redshift004 from './004-publicly-accessible.cf.js';
import redshift005 from './005-snapshot-retention.cf.js';
import redshift006 from './006-activity-logging.cf.js';

export const redshiftRules = [
  redshift001,
  redshift002,
  redshift003,
  redshift004,
  redshift005,
  redshift006
];

import tfRule001 from './001-ssl-parameter-groups.tf.js';
import tfRule002 from './002-default-master-username.tf.js';
import tfRule003 from './003-audit-logging.tf.js';
import tfRule004 from './004-publicly-accessible.tf.js';
import tfRule005 from './005-snapshot-retention.tf.js';
import tfRule006 from './006-activity-logging.tf.js';

export const tfRedshiftRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
];
