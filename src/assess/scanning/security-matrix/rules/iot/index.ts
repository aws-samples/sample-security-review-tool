import rule001 from './001-device-visibility.js';
import rule002 from './002-software-integrity.js';
import rule003 from './003-vulnerability-scanning.js';
import rule004 from './004-malware-prevention.js';
import rule006 from './006-resilience-testing.js';
import rule005 from './005-secure-transit.js';
import rule011 from './011-unique-identity.js';
import rule016 from './016-public-access.js';
import rule018 from './018-logging-strategy.js';
import rule031 from './031-cloudwatch-logging.js';
import rule032 from './032-separation-of-duties.js';
import rule033 from './033-vpc-privatelink.js';
import rule007 from './007-third-party-integrations.js';
import rule009 from './009-attack-surface-minimization.js';
import rule028 from './028-backup-recovery-plan.js';
import rule019 from './019-monitoring-alarms.js';
import rule020 from './020-device-defender-audit.js';
import rule023 from './023-certificate-management.js';
import rule024 from './024-certificate-revocation.js';
import rule030 from './030-device-defender-monitoring.js';

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
