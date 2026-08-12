import { ControlAdapter } from '../../../controls/types.js';

export interface Apigw003Adapter extends ControlAdapter {
  /** True when the template/plan contains a current-generation web ACL association covering this stage. */
  hasWebAclAssociation(): boolean;
  /** True when the only web ACL association covering this stage is an end-of-life legacy one. */
  hasLegacyWebAclAssociationOnly(): boolean;
  /**
   * True when the stage belongs to a newer-generation API type (HTTP or WebSocket API),
   * which cannot carry a stage-level web ACL association and is therefore out of scope.
   */
  belongsToNewerGenerationApi(): boolean;
}
