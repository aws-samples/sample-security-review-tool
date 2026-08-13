import { ControlAdapter } from '../../../controls/types.js';

export type ChildDirectedSetting = true | false | 'absent' | 'unknown' | 'other';

export interface Lex001Adapter extends ControlAdapter {
  childDirected(): ChildDirectedSetting;
}
