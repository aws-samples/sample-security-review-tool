import elasticBeanstalk001 from './001-vpc-configuration.js';
import elasticBeanstalk002 from './002-iam-instance-profile.js';
import elasticBeanstalk003 from './003-platform-updates.js';
import elasticBeanstalk004 from './004-s3-log-retention.js';

export const elasticBeanstalkRules = [
  elasticBeanstalk001,
  elasticBeanstalk002,
  elasticBeanstalk003,
  elasticBeanstalk004
];

export default elasticBeanstalkRules;

