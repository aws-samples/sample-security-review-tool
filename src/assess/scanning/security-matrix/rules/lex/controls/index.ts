import { RegisteredControl } from '../../../controls/types.js';
import { lex002Control } from '../lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../lex-002/lex-002.adapter.cfn.js';
import { Lex002TfAdapterFactory } from '../lex-002/lex-002.adapter.tf.js';

export const lexControls: RegisteredControl[] = [
  { control: lex002Control, cfnAdapter: new Lex002CfnAdapterFactory(), tfAdapter: new Lex002TfAdapterFactory() },
];
