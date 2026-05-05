import rule001 from './001-multi-az-deployment.cf.js';
import rule002 from './002-encryption-at-rest.cf.js';
import rule003 from './003-encryption-in-transit.cf.js';
import rule004 from './004-iam-database-authentication.cf.js';
import rule005 from './005-public-access.cf.js';
import rule006 from './006-secure-security-groups.cf.js';
import rule007 from './007-private-subnet-deployment.cf.js';
import rule008 from './008-delete-protection.cf.js';
import rule009 from './009-automated-backups.cf.js';
import rule010 from './010-aurora-backtrack.cf.js';
import rule011 from './011-event-notifications.cf.js';
import rule012 from './012-secrets-manager-credentials.cf.js';

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

import tfRule001 from './001-multi-az-deployment.tf.js';
import tfRule002 from './002-encryption-at-rest.tf.js';
import tfRule003 from './003-encryption-in-transit.tf.js';
import tfRule004 from './004-iam-database-authentication.tf.js';
import tfRule005 from './005-public-access.tf.js';
import tfRule006 from './006-secure-security-groups.tf.js';
import tfRule007 from './007-private-subnet-deployment.tf.js';
import tfRule008 from './008-delete-protection.tf.js';
import tfRule009 from './009-automated-backups.tf.js';
import tfRule010 from './010-aurora-backtrack.tf.js';
import tfRule011 from './011-event-notifications.tf.js';
import tfRule012 from './012-secrets-manager-credentials.tf.js';

export const tfRdsRules = [
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
  tfRule011,
  tfRule012,
];
