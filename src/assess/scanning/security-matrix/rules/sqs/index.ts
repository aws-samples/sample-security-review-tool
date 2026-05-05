export { default as Sqs001Rule } from './001-sqs-policy-restriction.cf.js';
export { default as Sqs003Rule } from './003-dead-letter-queue.cf.js';
import tfRule001 from './001-sqs-policy-restriction.tf.js';
import tfRule002 from './003-dead-letter-queue.tf.js';
import tfRule003 from './007-sqs-admin-usage-separation.tf.js';
import tfRule004 from './008-sqs-vpc-endpoint-enforcement.tf.js';

export const tfSqsRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
];
