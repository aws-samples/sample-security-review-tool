import Lex001Rule from './001-coppa-compliance.cf.js';
import Lex002Rule from './002-slot-obfuscation.cf.js';

export const lexRules = [
  Lex001Rule,
  Lex002Rule
];

export default lexRules;

import tfRule001 from './001-coppa-compliance.tf.js';
import tfRule002 from './002-slot-obfuscation.tf.js';

export const tfLexRules = [
  tfRule001,
  tfRule002,
];
