import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Lex001Adapter } from './lex-001.adapter.js';

const MISSING_DATA_PRIVACY = 'missing-data-privacy';

export class Lex001Control extends SecurityControl<Lex001Adapter> {
  constructor() {
    super({
      id: 'LEX-001',
      priority: 'HIGH',
      description: 'Lex bots must have the DataPrivacy child-directed setting explicitly set to true to comply with COPPA',
      remediationScenarios: [
        {
          scenario: MISSING_DATA_PRIVACY,
          intent: 'Every Lex bot must declare a data privacy setting whose child-directed value is a hard-coded boolean true, and it must still read that way in the resource as deployed rather than only in the source. Fix every bot in the file, including any kept as a non-compliant example, and every entry where the setting is declared as a list.',
        },
      ],
    });
  }

  protected evaluate(adapter: Lex001Adapter): ControlFinding | null {
    const childDirected = adapter.childDirected();
    if (childDirected === true || childDirected === 'unknown') return null;
    return {
      scenario: MISSING_DATA_PRIVACY,
      issue: 'Lex bot does not declare the child-directed data privacy setting as true, so COPPA compliance is not established',
    };
  }
}

export const lex001Control = new Lex001Control();
