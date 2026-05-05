import Cognito001Rule from './001-unauthenticated-privileges.cf.js';

export const cognitoRules = [
  Cognito001Rule
];

export default cognitoRules;

import tfRule001 from './001-unauthenticated-privileges.tf.js';

export const tfCognitoRules = [
  tfRule001,
];
