import { RegisteredControl } from '../../../controls/types.js';
import { s3001Control } from './s3-001.control.js';
import { CfnS3BucketAdapterFactory } from '../adapters/cfn-s3-bucket-adapter.js';
import { TfS3BucketAdapterFactory } from '../adapters/tf-s3-bucket-adapter.js';

export const s3Controls: RegisteredControl[] = [
  { control: s3001Control, cfnAdapter: new CfnS3BucketAdapterFactory(), tfAdapter: new TfS3BucketAdapterFactory() },
];
