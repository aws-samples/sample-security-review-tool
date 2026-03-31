import rule001 from './001-access-logging-least-privilege.js';
import rule005 from './005-cloudfront-origin-access-control.js';
import rule008 from './008-lifecycle-policies.js';

export const s3Rules = [
  rule001,
  rule005,
  rule008,
];