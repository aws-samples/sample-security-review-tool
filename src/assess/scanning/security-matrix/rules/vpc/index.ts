import rule001 from './001-multiple-azs.cf.js';
import rule002 from './002-routing-tables.cf.js';
import rule003 from './003-flow-log-retention.cf.js';

export const vpcConfigurationRules = [
  rule001,
  rule002,
  rule003
];

import tfRule001 from './001-multiple-azs.tf.js';
import tfRule002 from './002-routing-tables.tf.js';
import tfRule003 from './003-flow-log-retention.tf.js';

export const tfVpcRules = [
  tfRule001,
  tfRule002,
  tfRule003,
];
