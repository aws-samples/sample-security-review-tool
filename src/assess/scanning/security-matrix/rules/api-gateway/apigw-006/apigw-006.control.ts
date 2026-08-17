import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Apigw006Adapter } from './apigw-006.adapter.js';

const NO_METHOD_LOGGING_CONFIGURATION = 'no-method-logging-configuration';
const PARTIAL_METHOD_LOGGING_COVERAGE = 'partial-method-logging-coverage';
const LOGGING_LEVEL_NOT_ACCEPTED = 'logging-level-not-accepted';
const LOGGING_DISABLED_FOR_SOME_METHOD = 'logging-disabled-for-some-method';

const FINDINGS = {
  [NO_METHOD_LOGGING_CONFIGURATION]: {
    issue: 'API Gateway stage has no method-level logging configuration, so CloudWatch execution logging is effectively off for all methods',
    remediation: 'Enable CloudWatch execution logging for the API Gateway stage by adding a catch-all method-level logging setting that applies to every method and path, with the logging level set to INFO or ERROR.',
  },
  [PARTIAL_METHOD_LOGGING_COVERAGE]: {
    issue: 'API Gateway stage configures execution logging only for specific methods and paths, leaving the remaining methods without CloudWatch execution logging',
    remediation: 'Broaden the API Gateway stage method-level logging configuration so it applies to every method and path of the stage instead of individual methods, keeping the logging level at INFO or ERROR.',
  },
  [LOGGING_LEVEL_NOT_ACCEPTED]: {
    issue: 'API Gateway stage method-level logging configuration does not use an accepted execution logging level of INFO or ERROR',
    remediation: 'Change the execution logging level of the API Gateway stage method-level logging setting to INFO or ERROR so that execution logs are recorded for every method and path.',
  },
  [LOGGING_DISABLED_FOR_SOME_METHOD]: {
    issue: 'API Gateway stage has a method-level logging configuration that turns execution logging off for a specific method and path, so requests to that method are not logged',
    remediation: 'Raise the execution logging level of every narrower method-level logging setting of the API Gateway stage to INFO or ERROR, or remove those settings so the catch-all logging configuration applies to all methods and paths.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Apigw006Control extends SecurityControl<Apigw006Adapter, FindingKey> {
  constructor() {
    super({
      id: 'APIGW-006',
      priority: 'HIGH',
      description: 'API Gateway stages must have CloudWatch execution logging enabled, with the logging level set to INFO or ERROR for all methods (or via a catch-all method setting)',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Apigw006Adapter): FindingKey | null {
    if (!adapter.hasMethodLoggingConfiguration()) return NO_METHOD_LOGGING_CONFIGURATION;
    if (!adapter.hasCatchAllCoverage()) return PARTIAL_METHOD_LOGGING_COVERAGE;
    if (!adapter.hasAcceptedLoggingLevel()) return LOGGING_LEVEL_NOT_ACCEPTED;
    if (adapter.hasLoggingDisabledForSomeMethod()) return LOGGING_DISABLED_FOR_SOME_METHOD;
    return null;
  }
}

export const apigw006Control = new Apigw006Control();
