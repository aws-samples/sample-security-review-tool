import { RegisteredControl } from '../../../controls/types.js';
import { s3001Control } from '../s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../s3-001/s3-001.adapter.cfn.js';
import { S3001TfAdapterFactory } from '../s3-001/s3-001.adapter.tf.js';
import { s3008Control } from '../s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../s3-008/s3-008.adapter.cfn.js';
import { S3008TfAdapterFactory } from '../s3-008/s3-008.adapter.tf.js';

export const s3Controls: RegisteredControl[] = [
  { control: s3001Control, cfnAdapter: new S3001CfnAdapterFactory(), tfAdapter: new S3001TfAdapterFactory() },
  { control: s3008Control, cfnAdapter: new S3008CfnAdapterFactory(), tfAdapter: new S3008TfAdapterFactory() },
];
