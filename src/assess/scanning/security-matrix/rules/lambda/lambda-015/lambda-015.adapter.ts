import { ControlAdapter } from '../../../controls/types.js';

export interface Lambda015Adapter extends ControlAdapter {
  getImageUri(): string | undefined;
}
