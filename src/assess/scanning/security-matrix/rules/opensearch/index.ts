import esh001 from './001-vpc-deployment.cf.js';
import esh003 from './003-security-group-restrictions.cf.js';
import esh004 from './004-dedicated-master-nodes.cf.js';
import esh006 from './006-off-peak-window.cf.js';
import esh007 from './007-zone-awareness.cf.js';
import esh008 from './008-encryption-at-rest.cf.js';
import esh009 from './009-audit-logs.cf.js';
import esh010 from './010-access-policies.cf.js';
import esh011 from './011-node-to-node-encryption.cf.js';
import esh012 from './012-domain-endpoint-encryption.cf.js';

export const openSearchRules = [
  esh001,
  esh003,
  esh004,
  esh006,
  esh007,
  esh008,
  esh009,
  esh010,
  esh011,
  esh012
];

export default openSearchRules;
import tfRule001 from './001-vpc-deployment.tf.js';
import tfRule002 from './003-security-group-restrictions.tf.js';
import tfRule003 from './004-dedicated-master-nodes.tf.js';
import tfRule004 from './006-off-peak-window.tf.js';
import tfRule005 from './007-zone-awareness.tf.js';
import tfRule006 from './008-encryption-at-rest.tf.js';
import tfRule007 from './009-audit-logs.tf.js';
import tfRule008 from './010-access-policies.tf.js';
import tfRule009 from './011-node-to-node-encryption.tf.js';
import tfRule010 from './012-domain-endpoint-encryption.tf.js';

export const tfOpensearchRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
  tfRule007,
  tfRule008,
  tfRule009,
  tfRule010,
];
