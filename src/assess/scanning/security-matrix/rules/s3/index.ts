import rule001 from './001-access-logging-least-privilege.cf.js';
import rule005 from './005-cloudfront-origin-access-control.cf.js';
import rule008 from './008-lifecycle-policies.cf.js';

export const s3Rules = [
  rule001,
  rule005,
  rule008,
];
import tfRule001 from './001-access-logging-least-privilege.tf.js';
import tfRule002 from './005-cloudfront-origin-access-control.tf.js';
import tfRule003 from './008-lifecycle-policies.tf.js';

export const tfS3Rules = [
  tfRule001,
  tfRule002,
  tfRule003,
];
