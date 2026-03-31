// rule001 (FSx1 - Access limitation) is not implemented as access requirements depend on business and organizational policies that cannot be inferred automatically
import rule002 from './002-vpc-endpoints.js';
import rule003 from './003-system-access-auditing.js';
import rule004 from './004-data-level-access-logging.js';
import ruleN001 from './n001-security-groups-restrict-access.js';
import ruleN002 from './n002-restrict-ssh-api-access.js';
import ruleN003 from './n003-ssh-private-key-access.js';

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
