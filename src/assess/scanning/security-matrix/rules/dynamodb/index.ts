import { RegisteredControl } from '../../controls/types.js';
import { ddb002Control } from './ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from './ddb-002/ddb-002.adapter.cfn.js';
import { Ddb002TfAdapterFactory } from './ddb-002/ddb-002.adapter.tf.js';

export const dynamodbControls: RegisteredControl[] = [
  { control: ddb002Control, cfnAdapter: new Ddb002CfnAdapterFactory(), tfAdapter: new Ddb002TfAdapterFactory() },
];
