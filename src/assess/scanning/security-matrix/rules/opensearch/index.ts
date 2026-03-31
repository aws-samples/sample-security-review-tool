import esh001 from './001-vpc-deployment.js';
import esh003 from './003-security-group-restrictions.js';
import esh004 from './004-dedicated-master-nodes.js';
import esh006 from './006-off-peak-window.js';
import esh007 from './007-zone-awareness.js';
import esh008 from './008-encryption-at-rest.js';
import esh009 from './009-audit-logs.js';
import esh010 from './010-access-policies.js';
import esh011 from './011-node-to-node-encryption.js';
import esh012 from './012-domain-endpoint-encryption.js';

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