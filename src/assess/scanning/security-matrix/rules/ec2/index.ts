import rule002 from './002-least-privilege-roles.js';
import rule003 from './003-secure-security-groups.js';
import rule005 from './005-limited-egress-rules.js';
import rule009 from './009-termination-protection.js';
import rule014 from './014-public-ip-on-load-balancers.js';

// Note: EC27, EC28, and EC210 are not implemented as they're not mentioned in the documentation

export const ec2Rules = [
  // rule001, // Skipped: Runtime behaviors that cannot be fully determined from infrastructure-as-code templates alone
  rule002,
  rule003,
  // rule004, // Skipped: Depends on architecture intent which isn't always determinable from code alone
  rule005,
  // rule006, // Skipped: Fully covered by Checkov rule CKV_AWS_3
  rule009,
  // rule011, // Skipped: Guidance-oriented and difficult to fully validate in CloudFormation templates
  // rule012, // Skipped: Guidance-oriented and difficult to fully validate in CloudFormation templates
  // rule013, // Skipped: Fully covered by Checkov rule CKV_AWS_79
  rule014,
];

export {
  // rule001 as identityControlRule,         // Skipped: Runtime behaviors that cannot be fully determined from infrastructure-as-code templates alone
  rule002 as leastPrivilegeRolesRule,
  rule003 as secureSecurityGroupsRule,
  // rule004 as loadBalancerForPublicInstancesRule, // Skipped : Depends on architecture intent which isn't always determinable from code alone
  rule005 as limitedEgressRulesRule,
  // rule006 as ebsEncryptionRule,         // Skipped: Fully covered by Checkov rule CKV_AWS_3
  rule009 as terminationProtectionRule,
  // rule011 as limitedSoftwareInstallationRule, // Skipped: Guidance-oriented and difficult to fully validate in CloudFormation templates
  // rule012 as osPatchingMaintenanceRule,       // Skipped: Guidance-oriented and difficult to fully validate in CloudFormation templates
  // rule013 as useImdsv2Rule,             // Skipped: Fully covered by Checkov rule CKV_AWS_79
  rule014 as publicIpOnLoadBalancersRule,
};
