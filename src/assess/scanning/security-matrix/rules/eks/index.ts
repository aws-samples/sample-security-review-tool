import rule001 from './001-private-api-access.cf.js';
import rule002 from './002-control-plane-logs.cf.js';
import rule003 from './003-security-group-port-443.cf.js';
import rule005 from './005-tenant-separation.cf.js';
import rule008 from './008-irsa-aws-resources.cf.js';
import rule009 from './009-rbac-enabled.cf.js';
import rule010 from './010-opa-gatekeeper.cf.js';
import rule011 from './011-tenant-workload-isolation.cf.js';
import rule013 from './013-private-endpoint.cf.js';
import rule015 from './015-non-root-user.cf.js';
import rule016 from './016-audit-logs-enabled.cf.js';
import rule017 from './017-cluster-alerts.cf.js';
import rule018 from './018-kms-envelope-encryption.cf.js';

export const eksRules = [
  rule001,
  rule002,
  rule003,
  rule005,
  rule008,
  rule009,
  rule010,
  rule011,
  rule013,
  rule015,
  rule016,
  rule017,
  rule018
];

import tfRule001 from './001-private-api-access.tf.js';
import tfRule002 from './002-control-plane-logs.tf.js';
import tfRule003 from './003-security-group-port-443.tf.js';
import tfRule004 from './005-tenant-separation.tf.js';
import tfRule005 from './008-irsa-aws-resources.tf.js';
import tfRule006 from './009-rbac-enabled.tf.js';
import tfRule007 from './010-opa-gatekeeper.tf.js';
import tfRule008 from './011-tenant-workload-isolation.tf.js';
import tfRule009 from './013-private-endpoint.tf.js';
import tfRule010 from './015-non-root-user.tf.js';
import tfRule011 from './016-audit-logs-enabled.tf.js';
import tfRule012 from './017-cluster-alerts.tf.js';
import tfRule013 from './018-kms-envelope-encryption.tf.js';

export const tfEksRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
  tfRule007,
  tfRule008,
  tfRule009,
  tfRule010,
  tfRule011,
  tfRule012,
  tfRule013,
];
