import { RegisteredControl } from '../../controls/types.js';
import { ath001Control } from './ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from './ath-001/ath-001.adapter.cfn.js';
import { Ath001TfAdapterFactory } from './ath-001/ath-001.adapter.tf.js';
import { ath002Control } from './ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from './ath-002/ath-002.adapter.cfn.js';
import { Ath002TfAdapterFactory } from './ath-002/ath-002.adapter.tf.js';

export const athenaControls: RegisteredControl[] = [
  { control: ath001Control, cfnAdapter: new Ath001CfnAdapterFactory(), tfAdapter: new Ath001TfAdapterFactory() },
  { control: ath002Control, cfnAdapter: new Ath002CfnAdapterFactory(), tfAdapter: new Ath002TfAdapterFactory() },
];
