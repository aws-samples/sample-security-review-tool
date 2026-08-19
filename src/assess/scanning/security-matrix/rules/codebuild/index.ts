
export const codebuildRules = [
];

export {
};

export const tfCodebuildRules = [
];

import { RegisteredControl } from '../../controls/types.js';
import { codebuild009Control } from './codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from './codebuild-009/codebuild-009.adapter.cfn.js';
import { Codebuild009TfAdapterFactory } from './codebuild-009/codebuild-009.adapter.tf.js';

export const codebuildControls: RegisteredControl[] = [
  { control: codebuild009Control, cfnAdapter: new Codebuild009CfnAdapterFactory(), tfAdapter: new Codebuild009TfAdapterFactory() },
];
