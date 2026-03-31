import EMR001Rule from './001-private-subnet.js';
import EMR002Rule from './002-s3-logging.js';
import EMR006Rule from './006-authentication.js';
import EMR007Rule from './007-security-group-ingress.js';

export const emrRules = [
  EMR001Rule,
  EMR002Rule,
  EMR006Rule,
  EMR007Rule,
];

export default emrRules;