import SageMaker001Rule from './001-vpc-required.js';
import SageMaker003Rule from './003-no-direct-internet.js';
import SageMaker004Rule from './004-studio-experience.js';
import SageMaker005Rule from './005-vpc-security-groups.js';
import SageMaker006Rule from './006-training-vpc-isolation.js';
import SageMaker008Rule from './008-data-access-restriction.js';
import SageMaker009Rule from './009-no-root-access.js';
import SageMaker010Rule from './010-role-reuse.js';

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
