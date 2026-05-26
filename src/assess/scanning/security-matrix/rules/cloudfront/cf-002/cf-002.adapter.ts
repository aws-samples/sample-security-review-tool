import { ControlAdapter } from '../../../controls/types.js';

export interface Cf002Adapter extends ControlAdapter {
  hasWebAclAssociation(): boolean;
}
