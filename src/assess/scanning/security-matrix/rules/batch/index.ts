import rule001 from './001-secure-security-groups.js';
import rule002 from './002-least-privilege-roles.js';

export const batchRules = [
  rule001,
  rule002
];

export {
  rule001 as secureSecurityGroupsRule,
  rule002 as leastPrivilegeRolesRule
};