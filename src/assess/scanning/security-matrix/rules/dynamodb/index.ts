import rule002 from './002-cloudtrail-data-events.cf.js';

export const dynamodbRules = [
  rule002
];

export {
  rule002 as cloudtrailDataEventsRule
};

import tfRule001 from './002-cloudtrail-data-events.tf.js';

export const tfDynamodbRules = [
  tfRule001,
];
