import rule001 from './001-multi-az-configuration.js';
import rule002 from './002-redis-auth.js';

export const elasticacheRules = [
    rule001,
    rule002
];

export {
    rule001 as multiAzConfigurationRule,
    rule002 as redisAuthRule
};
