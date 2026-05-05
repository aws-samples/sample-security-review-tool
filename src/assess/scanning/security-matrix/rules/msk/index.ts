import msk002 from './002-client-broker-encryption.cf.js';
import msk003 from './003-tls-encryption.cf.js';
import msk004 from './004-iam-authentication.cf.js';
import msk005 from './005-acl-authorization.cf.js';
import msk006 from './006-broker-log-delivery.cf.js';
import msk007 from './007-zookeeper-security-groups.cf.js';
import msk008 from './008-zookeeper-tls.cf.js';
import msk009 from './009-cloudtrail-monitoring.cf.js';

export const mskRules = [
  msk002,
  msk003,
  msk004,
  msk005,
  msk006,
  msk007,
  msk008,
  msk009
];

export default mskRules;
import tfRule001 from './002-client-broker-encryption.tf.js';
import tfRule002 from './003-tls-encryption.tf.js';
import tfRule003 from './004-iam-authentication.tf.js';
import tfRule004 from './005-acl-authorization.tf.js';
import tfRule005 from './006-broker-log-delivery.tf.js';
import tfRule006 from './007-zookeeper-security-groups.tf.js';
import tfRule007 from './008-zookeeper-tls.tf.js';
import tfRule008 from './009-cloudtrail-monitoring.tf.js';

export const tfMskRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
  tfRule007,
  tfRule008,
];
