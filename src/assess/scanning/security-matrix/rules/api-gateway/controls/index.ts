import { RegisteredControl } from '../../../controls/types.js';
import { apigw001Control } from '../apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../apigw-001/apigw-001.adapter.cfn.js';
import { Apigw001TfAdapterFactory } from '../apigw-001/apigw-001.adapter.tf.js';

export const apiGatewayControls: RegisteredControl[] = [
  { control: apigw001Control, cfnAdapter: new Apigw001CfnAdapterFactory(), tfAdapter: new Apigw001TfAdapterFactory() },
];
