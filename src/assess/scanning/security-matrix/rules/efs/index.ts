import rule003 from './003-security-groups-limit-traffic.cf.js';
import rule006 from './006-encryption-kms.cf.js';
import rule007 from './007-automatic-backups.cf.js';

// Note: EFS1 and EFS2 are not implemented as they're not mentioned in the documentation
// Note: EFS4 (UID/GID management) is not implemented as UID/GID consistency depends on system-level configuration across multiple machines, which cannot be fully inferred from infrastructure code alone
// Note: EFS5 (Access points) is not implemented as whether applications use access points is an architectural choice and may not be fully visible in infrastructure code

export const efsRules = [
  rule003,
  rule006,
  rule007,
];

export {
  rule003 as securityGroupsLimitTrafficRule,
  rule006 as encryptionKmsRule,
  rule007 as automaticBackupsRule,
};

import tfRule001 from './003-security-groups-limit-traffic.tf.js';
import tfRule002 from './006-encryption-kms.tf.js';
import tfRule003 from './007-automatic-backups.tf.js';

export const tfEfsRules = [
  tfRule001,
  tfRule002,
  tfRule003,
];
