
export const codedeployRules = [
];

export {
};

export const tfCodedeployRules = [
];

import { RegisteredControl } from '../../controls/types.js';
import { codedeploy001Control } from './codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from './codedeploy-001/codedeploy-001.adapter.cfn.js';
import { Codedeploy001TfAdapterFactory } from './codedeploy-001/codedeploy-001.adapter.tf.js';

export const codedeployControls: RegisteredControl[] = [
  { control: codedeploy001Control, cfnAdapter: new Codedeploy001CfnAdapterFactory(), tfAdapter: new Codedeploy001TfAdapterFactory() },
];
