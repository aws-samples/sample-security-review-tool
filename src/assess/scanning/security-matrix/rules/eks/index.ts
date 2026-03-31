import rule001 from './001-private-api-access.js';
import rule002 from './002-control-plane-logs.js';
import rule003 from './003-security-group-port-443.js';
import rule005 from './005-tenant-separation.js';
import rule008 from './008-irsa-aws-resources.js';
import rule009 from './009-rbac-enabled.js';
import rule010 from './010-opa-gatekeeper.js';
import rule011 from './011-tenant-workload-isolation.js';
import rule013 from './013-private-endpoint.js';
import rule015 from './015-non-root-user.js';
import rule016 from './016-audit-logs-enabled.js';
import rule017 from './017-cluster-alerts.js';
import rule018 from './018-kms-envelope-encryption.js';

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
