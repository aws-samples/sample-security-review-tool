import SageMaker001Rule from './001-vpc-required.cf.js';
import SageMaker003Rule from './003-no-direct-internet.cf.js';
import SageMaker004Rule from './004-studio-experience.cf.js';
import SageMaker005Rule from './005-vpc-security-groups.cf.js';
import SageMaker006Rule from './006-training-vpc-isolation.cf.js';
import SageMaker008Rule from './008-data-access-restriction.cf.js';
import SageMaker009Rule from './009-no-root-access.cf.js';
import SageMaker010Rule from './010-role-reuse.cf.js';

export const sagemakerRules = [
  SageMaker001Rule,
  SageMaker003Rule,
  SageMaker004Rule,
  SageMaker005Rule,
  SageMaker006Rule,
  SageMaker008Rule,
  SageMaker009Rule,
  SageMaker010Rule,
];

export default sagemakerRules;

import tfRule001 from './001-vpc-required.tf.js';
import tfRule002 from './003-no-direct-internet.tf.js';
import tfRule003 from './004-studio-experience.tf.js';
import tfRule004 from './005-vpc-security-groups.tf.js';
import tfRule005 from './006-training-vpc-isolation.tf.js';
import tfRule006 from './008-data-access-restriction.tf.js';
import tfRule007 from './009-no-root-access.tf.js';
import tfRule008 from './010-role-reuse.tf.js';

export const tfSagemakerRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
  tfRule007,
  tfRule008,
];
