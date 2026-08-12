import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Apigw003Adapter } from './apigw-003.adapter.js';
import { externalCheck } from '../../../../remediation/external-check.js';

const MISSING_ASSOCIATION = 'missing-web-acl-association';
const LEGACY_ASSOCIATION = 'legacy-web-acl-association';

export class Apigw003Control extends SecurityControl<Apigw003Adapter> {
  constructor() {
    super({
      id: 'APIGW-003',
      priority: 'HIGH',
      description: 'Public-facing API Gateway stages must have an AWS WAF web ACL associated with them',
      remediationScenarios: [
        {
          scenario: MISSING_ASSOCIATION,
          intent:
            'Associate a current-generation (WAFv2) web application firewall web ACL with the flagged REST API stage. A legacy/end-of-life regional WAF association does not satisfy the control and must be replaced by a current-generation association.\n\nThe association must be defined as its own current-generation web ACL association resource in the same template/plan/module as the stage, and it must satisfy all of the following:\n\n1. Web ACL identifier: the association must specify a non-empty web ACL identifier/ARN (a reference/attribute of a current-generation web ACL resource, or a non-blank literal string). An absent, null, or blank value makes the association invalid.\n\n2. Target resource identifier: the association\'s target resource ARN must clearly identify the flagged stage. Any of these forms is accepted:\n   - A value that resolves to the stage\'s own resource identifier/logical name (or a string that contains it).\n   - A full API Gateway stage ARN whose path ends with `/restapis/<rest-api-id>/stages/<stage-name>`, where:\n     * `<rest-api-id>` must resolve to the same value used as the stage\'s REST API reference (i.e. reference the same REST API resource the stage belongs to), and\n     * `<stage-name>` must identify the flagged stage: either its configured stage name value, or a reference to the stage resource itself, since such a reference resolves to the stage name.\n   - A stage ARN ending with `/restapis/<rest-api-id>/stages/*` to cover all stages of that REST API.\n\n   When composing the ARN by string concatenation, the final segment may be either the stage-name value or a reference to the stage resource. Alternatively, avoid concatenation entirely and set the target to the stage resource reference/identifier.\n\n3. Scope: the web ACL used must be a regional-scope current-generation web ACL, since API Gateway stages are regional resources.\n\nNotes:\n- Stages belonging to newer-generation HTTP or WebSocket APIs are out of scope; do not add stage-level associations for them.\n- Keep the existing scenario coverage intact: only add the current-generation association for the stage reported as missing protection, and for the stage reported as legacy-only, replace the legacy association with a current-generation one (unless the fixture intentionally preserves the legacy-only case).',
        },
        {
          scenario: LEGACY_ASSOCIATION,
          intent:
            'Replace the end-of-life legacy web application firewall association with a current-generation web ACL association covering the API stage.',
        },
      ],
      relatedRules: [externalCheck('CKV_AWS_192')],
    });
  }

  protected evaluate(adapter: Apigw003Adapter): ControlFinding | null {
    if (adapter.belongsToNewerGenerationApi()) return null;
    if (adapter.hasWebAclAssociation()) return null;
    if (adapter.hasLegacyWebAclAssociationOnly()) {
      return {
        scenario: LEGACY_ASSOCIATION,
        issue:
          'The API stage is protected only by an end-of-life legacy generation web application firewall web ACL association',
      };
    }
    return {
      scenario: MISSING_ASSOCIATION,
      issue: 'The API stage is not protected by any web application firewall web ACL association',
    };
  }
}

export const apigw003Control = new Apigw003Control();
