import rule001 from './001-private-subnet-alb.js';
import rule002 from './002-sensitive-parameters.js';
import rule003 from './003-task-network-isolation.js';
// rule004 (ECS4 - Metrics monitoring) is not implemented as whether metrics are sufficient and properly monitored depends on the application context, which cannot be fully determined automatically
import rule005 from './005-minimal-iam-role.js';
import rule006 from './006-least-privilege-policies.js';
import rule007 from './007-logging-enabled.js';
// rule008 (ECS8 - No sensitive logging) is not implemented as detecting sensitive data in logs often requires understanding application context, which cannot be fully automated
// rule009 (ECS9 - Approved libraries) is not implemented as determining license approval often requires human judgment and policy context that cannot be fully inferred from code alone
// rule010 (ECS10 - Container least privilege) removed - was an advisory rule that always triggered without detecting actual issues
import rule011 from './011-awsvpc-network-mode.js';

export const ecsRules = [
  rule001,
  rule002,
  rule003,
  rule005,
  rule006,
  rule007,
  rule011,
];

export {
  rule001 as privateSubnetAlbRule,
  rule002 as sensitiveParametersRule,
  rule003 as taskNetworkIsolationRule,
  rule005 as minimalIamRoleRule,
  rule006 as leastPrivilegePoliciesRule,
  rule007 as loggingEnabledRule,
  rule011 as awsvpcNetworkModeRule,
};
