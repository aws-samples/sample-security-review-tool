import rule001 from './001-backup-retention.cf.js';
import rule002 from './002-log-exports.cf.js';
import rule003 from './003-restrict-ingress.cf.js';

export const documentdbRules = [
  rule001,
  rule002,
  rule003
];
import tfRule001 from './001-backup-retention.tf.js';
import tfRule002 from './002-log-exports.tf.js';
import tfRule003 from './003-restrict-ingress.tf.js';

export const tfDocumentdbRules = [
  tfRule001,
  tfRule002,
  tfRule003,
];
