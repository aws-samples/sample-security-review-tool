// rule001 (FSx1 - Access limitation) is not implemented as access requirements depend on business and organizational policies that cannot be inferred automatically
import rule002 from './002-vpc-endpoints.cf.js';
import rule003 from './003-system-access-auditing.cf.js';
import rule004 from './004-data-level-access-logging.cf.js';
import ruleN001 from './n001-security-groups-restrict-access.cf.js';
import ruleN002 from './n002-restrict-ssh-api-access.cf.js';
import ruleN003 from './n003-ssh-private-key-access.cf.js';

export const fsxRules = [
  rule002,
  rule003,
  rule004,
  ruleN001,
  ruleN002,
  ruleN003,
];

export {
  rule002 as vpcEndpointsRule,
  rule003 as systemAccessAuditingRule,
  rule004 as dataLevelAccessLoggingRule,
  ruleN001 as securityGroupsRestrictAccessRule,
  ruleN002 as restrictSshApiAccessRule,
  ruleN003 as sshPrivateKeyAccessRule,
};

import tfRule001 from './002-vpc-endpoints.tf.js';
import tfRule002 from './003-system-access-auditing.tf.js';
import tfRule003 from './004-data-level-access-logging.tf.js';
import tfRule004 from './n001-security-groups-restrict-access.tf.js';
import tfRule005 from './n002-restrict-ssh-api-access.tf.js';
import tfRule006 from './n003-ssh-private-key-access.tf.js';

export const tfFsxRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
];
