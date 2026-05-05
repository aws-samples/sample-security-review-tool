import rule001 from './001-multi-az-configuration.cf.js';
import rule002 from './002-redis-auth.cf.js';

export const elasticacheRules = [
    rule001,
    rule002
];

export {
    rule001 as multiAzConfigurationRule,
    rule002 as redisAuthRule
};

import tfRule001 from './001-multi-az-configuration.tf.js';
import tfRule002 from './002-redis-auth.tf.js';

export const tfElasticacheRules = [
  tfRule001,
  tfRule002,
];
