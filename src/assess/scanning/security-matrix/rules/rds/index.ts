import rule001 from './001-multi-az-deployment.js';
import rule002 from './002-encryption-at-rest.js';
import rule003 from './003-encryption-in-transit.js';
import rule004 from './004-iam-database-authentication.js';
import rule005 from './005-public-access.js';
import rule006 from './006-secure-security-groups.js';
import rule007 from './007-private-subnet-deployment.js';
import rule008 from './008-delete-protection.js';
import rule009 from './009-automated-backups.js';
import rule010 from './010-aurora-backtrack.js';
import rule011 from './011-event-notifications.js';
import rule012 from './012-secrets-manager-credentials.js';

export const rdsRules = [
  rule001,
  rule002,
  rule003,
  rule004,
  rule005,
  rule006,
  rule007,
  rule008,
  rule009,
  rule010,
  rule011,
  rule012
];

export {
  rule001 as multiAzDeploymentRule,
  rule002 as encryptionAtRestRule,
  rule003 as encryptionInTransitRule,
  rule004 as iamDatabaseAuthenticationRule,
  rule005 as publicAccessRule,
  rule006 as secureSecurityGroupsRule,
  rule007 as privateSubnetDeploymentRule,
  rule008 as deleteProtectionRule,
  rule009 as automatedBackupsRule,
  rule010 as auroraBacktrackRule,
  rule011 as eventNotificationsRule,
  rule012 as secretsManagerCredentialsRule
};
