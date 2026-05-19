import { RegisteredControl } from '../../../controls/types.js';
import { CfnS3AdapterFactory } from '../adapters/cfn-s3-adapter.js';
import { TfS3AdapterFactory } from '../adapters/tf-s3-adapter.js';
import { s3005Control } from './s3-005.control.js';

export const s3Controls: RegisteredControl[] = [
  { control: s3005Control, cfnAdapter: new CfnS3AdapterFactory(), tfAdapter: new TfS3AdapterFactory() },
];