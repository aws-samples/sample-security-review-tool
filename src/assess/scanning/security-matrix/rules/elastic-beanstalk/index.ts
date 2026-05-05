import elasticBeanstalk001 from './001-vpc-configuration.cf.js';
import elasticBeanstalk002 from './002-iam-instance-profile.cf.js';
import elasticBeanstalk003 from './003-platform-updates.cf.js';
import elasticBeanstalk004 from './004-s3-log-retention.cf.js';

export const elasticBeanstalkRules = [
  elasticBeanstalk001,
  elasticBeanstalk002,
  elasticBeanstalk003,
  elasticBeanstalk004
];

export default elasticBeanstalkRules;


import tfRule001 from './001-vpc-configuration.tf.js';
import tfRule002 from './002-iam-instance-profile.tf.js';
import tfRule003 from './003-platform-updates.tf.js';
import tfRule004 from './004-s3-log-retention.tf.js';

export const tfElasticBeanstalkRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
];
