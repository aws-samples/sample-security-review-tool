import rule001 from './001-device-visibility.cf.js';
import rule002 from './002-software-integrity.cf.js';
import rule003 from './003-vulnerability-scanning.cf.js';
import rule004 from './004-malware-prevention.cf.js';
import rule006 from './006-resilience-testing.cf.js';
import rule005 from './005-secure-transit.cf.js';
import rule011 from './011-unique-identity.cf.js';
import rule016 from './016-public-access.cf.js';
import rule018 from './018-logging-strategy.cf.js';
import rule031 from './031-cloudwatch-logging.cf.js';
import rule032 from './032-separation-of-duties.cf.js';
import rule033 from './033-vpc-privatelink.cf.js';
import rule007 from './007-third-party-integrations.cf.js';
import rule009 from './009-attack-surface-minimization.cf.js';
import rule028 from './028-backup-recovery-plan.cf.js';
import rule019 from './019-monitoring-alarms.cf.js';
import rule020 from './020-device-defender-audit.cf.js';
import rule023 from './023-certificate-management.cf.js';
import rule024 from './024-certificate-revocation.cf.js';
import rule030 from './030-device-defender-monitoring.cf.js';

export const iotRules = [
  rule001,
  rule002,
  rule003,
  rule004,
  rule006,
  rule005,
  rule007,
  rule009,
  rule011,
  rule016,
  rule018,
  rule019,
  rule020,
  rule023,
  rule024,
  rule028,
  rule030,
  rule031,
  rule032,
  rule033
];

export {
  rule001 as deviceVisibilityRule,
  rule002 as softwareIntegrityRule,
  rule003 as vulnerabilityScanningRule,
  rule004 as malwarePreventionRule,
  rule006 as resilienceTestingRule,
  rule005 as secureTransitRule,
  rule007 as thirdPartyIntegrationsRule,
  rule009 as attackSurfaceMinimizationRule,
  rule011 as uniqueIdentityRule,
  rule016 as publicAccessRule,
  rule018 as loggingStrategyRule,
  rule031 as iotSiteWiseCloudwatchLoggingRule,
  rule032 as separationOfDutiesRule,
  rule033 as iotSiteWiseVpcPrivateLinkRule,
  rule019 as monitoringAlarmsRule,
  rule020 as deviceDefenderAuditRule,
  rule023 as certificateManagementRule,
  rule024 as certificateRevocationRule,
  rule028 as backupRecoveryPlanRule,
  rule030 as deviceDefenderMonitoringRule
};

import tfRule001 from './001-device-visibility.tf.js';
import tfRule002 from './002-software-integrity.tf.js';
import tfRule003 from './003-vulnerability-scanning.tf.js';
import tfRule004 from './004-malware-prevention.tf.js';
import tfRule005 from './005-secure-transit.tf.js';
import tfRule006 from './006-resilience-testing.tf.js';
import tfRule007 from './007-third-party-integrations.tf.js';
import tfRule008 from './009-attack-surface-minimization.tf.js';
import tfRule009 from './011-unique-identity.tf.js';
import tfRule010 from './016-public-access.tf.js';
import tfRule011 from './018-logging-strategy.tf.js';
import tfRule012 from './019-monitoring-alarms.tf.js';
import tfRule013 from './020-device-defender-audit.tf.js';
import tfRule014 from './023-certificate-management.tf.js';
import tfRule015 from './024-certificate-revocation.tf.js';
import tfRule016 from './028-backup-recovery-plan.tf.js';
import tfRule017 from './030-device-defender-monitoring.tf.js';
import tfRule018 from './031-cloudwatch-logging.tf.js';
import tfRule019 from './032-separation-of-duties.tf.js';
import tfRule020 from './033-vpc-privatelink.tf.js';

export const tfIotRules = [
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
  tfRule013,
  tfRule014,
  tfRule015,
  tfRule016,
  tfRule017,
  tfRule018,
  tfRule019,
  tfRule020,
];
