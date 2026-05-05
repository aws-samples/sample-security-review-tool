import O001Rule from './001-service-access-monitoring.cf.js';
import O002Rule from './002-restrict-admin-privileges.cf.js';

export const organizationsRules = [
  O001Rule,
  O002Rule,
];
import tfRule001 from './001-service-access-monitoring.tf.js';
import tfRule002 from './002-restrict-admin-privileges.tf.js';

export const tfOrganizationsRules = [
  tfRule001,
  tfRule002,
];
