import rule001 from './001-secure-security-groups.cf.js';
import rule002 from './002-least-privilege-roles.cf.js';

export const batchRules = [
  rule001,
  rule002
];

export {
  rule001 as secureSecurityGroupsRule,
  rule002 as leastPrivilegeRolesRule
};
import tfRule001 from './001-secure-security-groups.tf.js';
import tfRule002 from './002-least-privilege-roles.tf.js';

export const tfBatchRules = [
  tfRule001,
  tfRule002,
];
