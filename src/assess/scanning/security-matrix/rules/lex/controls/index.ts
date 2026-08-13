import { RegisteredControl } from '../../../controls/types.js';
import { lex001Control } from '../lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../lex-001/lex-001.adapter.cfn.js';
import { Lex001TfAdapterFactory } from '../lex-001/lex-001.adapter.tf.js';
import { lex002Control } from '../lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../lex-002/lex-002.adapter.cfn.js';
import { Lex002TfAdapterFactory } from '../lex-002/lex-002.adapter.tf.js';

export const lexControls: RegisteredControl[] = [
  { control: lex001Control, cfnAdapter: new Lex001CfnAdapterFactory(), tfAdapter: new Lex001TfAdapterFactory() },
  { control: lex002Control, cfnAdapter: new Lex002CfnAdapterFactory(), tfAdapter: new Lex002TfAdapterFactory() },
];
