import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Ath001Adapter } from './ath-001.adapter.js';

const KMS_OPTIONS = ['SSE_KMS', 'CSE_KMS'];
const VALID_OPTIONS = ['SSE_S3', ...KMS_OPTIONS];

const MISSING_ENCRYPTION = 'missing-query-result-encryption';
const MISSING_KMS_KEY = 'missing-kms-key';
const CONFIGURATION_NOT_ENFORCED = 'workgroup-configuration-not-enforced';

export class Ath001Control extends SecurityControl<Ath001Adapter> {
  constructor() {
    super({
      id: 'ATH-001',
      priority: 'HIGH',
      description: 'Athena workgroups must have query result encryption enabled using SSE_S3, SSE_KMS, or CSE_KMS, with a KMS key specified when SSE_KMS or CSE_KMS is used',
      remediationScenarios: [
        {
          scenario: MISSING_ENCRYPTION,
          intent: 'Enable encryption of Athena query results for this workgroup by selecting one of the supported encryption options (S3-managed keys, KMS server-side encryption, or KMS client-side encryption).',
        },
        {
          scenario: MISSING_KMS_KEY,
          intent: 'The workgroup selects a KMS-based query result encryption option but supplies no KMS key. Add a KMS key, set to a concrete non-empty value, inside the same query result encryption settings as the encryption option, keeping that option unchanged. Fix only the workgroup carrying this finding.',
        },
        {
          scenario: CONFIGURATION_NOT_ENFORCED,
          intent: 'Make the workgroup\'s own result settings authoritative so that they always override any settings a client submits with a query, keeping the configured query result encryption in effect.',
        },
      ],
    });
  }

  protected evaluate(adapter: Ath001Adapter): ControlFinding | null {
    if (adapter.isEncryptionUnknown()) return null;

    const encryptionFinding = this.evaluateEncryption(adapter);
    if (encryptionFinding) return encryptionFinding;

    return this.evaluateEnforcement(adapter);
  }

  private evaluateEncryption(adapter: Ath001Adapter): ControlFinding | null {
    const option = adapter.getEncryptionOption();
    if (!option || !VALID_OPTIONS.includes(option)) {
      return {
        scenario: MISSING_ENCRYPTION,
        issue: 'Athena workgroup does not specify a supported query result encryption option, so query results may be stored unencrypted',
      };
    }

    if (KMS_OPTIONS.includes(option) && !adapter.hasKmsKey()) {
      return {
        scenario: MISSING_KMS_KEY,
        issue: 'Athena workgroup uses KMS-based query result encryption but no KMS key is specified',
      };
    }

    return null;
  }

  private evaluateEnforcement(adapter: Ath001Adapter): ControlFinding | null {
    if (adapter.isConfigurationEnforced() !== false) return null;
    return {
      scenario: CONFIGURATION_NOT_ENFORCED,
      issue: 'Athena workgroup does not force its own result settings over client-submitted settings, so clients can run queries with unencrypted result settings',
    };
  }
}

export const ath001Control = new Ath001Control();
