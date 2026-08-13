import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Lambda005Adapter } from './lambda-005.adapter.js';

const WILDCARD_GRANT = 'wildcard-action-and-resource';
const BROAD_MANAGED_POLICY = 'overly-broad-managed-policy';

export class Lambda005Control extends SecurityControl<Lambda005Adapter> {
  constructor() {
    super({
      id: 'LAMBDA-005',
      priority: 'HIGH',
      description: 'IAM roles used by Lambda functions must not grant wildcard actions paired with wildcard resources in inline policies, nor be attached to overly broad managed policies (such as AdministratorAccess, PowerUserAccess, or other FullAccess/Admin-level policies); they must instead be restricted to the specific actions and resource ARNs the function requires.',
      remediationScenarios: [
        {
          scenario: WILDCARD_GRANT,
          intent: 'Replace the all-actions-on-all-resources permission grant on the serverless function execution role with grants limited to the specific actions and the specific resource identifiers the function needs.',
        },
        {
          scenario: BROAD_MANAGED_POLICY,
          intent: 'Detach the administrator-level or service-wide predefined permission set from the serverless function execution role and grant instead a narrowly scoped permission set covering only the actions and resources the function needs.',
        },
      ],
    });
  }

  protected evaluate(adapter: Lambda005Adapter): ControlFinding | null {
    if (!adapter.isLambdaExecutionRole()) return null;

    if (adapter.grantsWildcardActionOnAllResources()) {
      return {
        scenario: WILDCARD_GRANT,
        issue: 'The execution role of a serverless function grants all actions on all resources, far exceeding least privilege.',
      };
    }

    if (adapter.usesOverlyBroadManagedPolicy()) {
      return {
        scenario: BROAD_MANAGED_POLICY,
        issue: 'The execution role of a serverless function is attached to an administrator-level or service-wide predefined permission set, far exceeding least privilege.',
      };
    }

    return null;
  }
}

export const lambda005Control = new Lambda005Control();
