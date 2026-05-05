import rule001 from './001-private-subnet-alb.cf.js';
import rule002 from './002-sensitive-parameters.cf.js';
import rule003 from './003-task-network-isolation.cf.js';
// rule004 (ECS4 - Metrics monitoring) is not implemented as whether metrics are sufficient and properly monitored depends on the application context, which cannot be fully determined automatically
import rule005 from './005-minimal-iam-role.cf.js';
import rule006 from './006-least-privilege-policies.cf.js';
import rule007 from './007-logging-enabled.cf.js';
// rule008 (ECS8 - No sensitive logging) is not implemented as detecting sensitive data in logs often requires understanding application context, which cannot be fully automated
// rule009 (ECS9 - Approved libraries) is not implemented as determining license approval often requires human judgment and policy context that cannot be fully inferred from code alone
// rule010 (ECS10 - Container least privilege) removed - was an advisory rule that always triggered without detecting actual issues
import rule011 from './011-awsvpc-network-mode.cf.js';

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

import tfRule001 from './001-private-subnet-alb.tf.js';
import tfRule002 from './002-sensitive-parameters.tf.js';
import tfRule003 from './003-task-network-isolation.tf.js';
import tfRule004 from './005-minimal-iam-role.tf.js';
import tfRule005 from './006-least-privilege-policies.tf.js';
import tfRule006 from './007-logging-enabled.tf.js';
import tfRule007 from './011-awsvpc-network-mode.tf.js';

export const tfEcsRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
  tfRule007,
];
