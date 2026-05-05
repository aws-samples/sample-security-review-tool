import EMR001Rule from './001-private-subnet.cf.js';
import EMR002Rule from './002-s3-logging.cf.js';
import EMR006Rule from './006-authentication.cf.js';
import EMR007Rule from './007-security-group-ingress.cf.js';

export const emrRules = [
  EMR001Rule,
  EMR002Rule,
  EMR006Rule,
  EMR007Rule,
];

export default emrRules;
import tfRule001 from './001-private-subnet.tf.js';
import tfRule002 from './002-s3-logging.tf.js';
import tfRule003 from './006-authentication.tf.js';
import tfRule004 from './007-security-group-ingress.tf.js';

export const tfEmrRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
];
