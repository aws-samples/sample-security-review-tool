import msk002 from './002-client-broker-encryption.js';
import msk003 from './003-tls-encryption.js';
import msk004 from './004-iam-authentication.js';
import msk005 from './005-acl-authorization.js';
import msk006 from './006-broker-log-delivery.js';
import msk007 from './007-zookeeper-security-groups.js';
import msk008 from './008-zookeeper-tls.js';
import msk009 from './009-cloudtrail-monitoring.js';

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