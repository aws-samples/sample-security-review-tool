import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Ath001Adapter } from './ath-001.adapter.js';

const KMS_OPTIONS = ['SSE_KMS', 'CSE_KMS'];
const VALID_OPTIONS = ['SSE_S3', ...KMS_OPTIONS];

const MISSING_ENCRYPTION = 'missing-query-result-encryption';
const MISSING_KMS_KEY = 'missing-kms-key';
const CONFIGURATION_NOT_ENFORCED = 'workgroup-configuration-not-enforced';

const FINDINGS = {
  [MISSING_ENCRYPTION]: {
    issue: 'Athena workgroup does not specify a supported query result encryption option, so query results may be stored unencrypted',
    remediation: 'Enable encryption of Athena query results for this workgroup by selecting one of the supported encryption options (S3-managed keys, KMS server-side encryption, or KMS client-side encryption).',
  },
  [MISSING_KMS_KEY]: {
    issue: 'Athena workgroup uses KMS-based query result encryption but no KMS key is specified',
    remediation: 'The workgroup selects a KMS-based query result encryption option but supplies no KMS key. Add a KMS key, set to a concrete non-empty value, inside the same query result encryption settings as the encryption option, keeping that option unchanged. Fix only the workgroup carrying this finding.',
  },
  [CONFIGURATION_NOT_ENFORCED]: {
    issue: 'Athena workgroup does not force its own result settings over client-submitted settings, so clients can run queries with unencrypted result settings',
    remediation: 'Make the workgroup\'s own result settings authoritative so that they always override any settings a client submits with a query, keeping the configured query result encryption in effect.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Ath001Control extends SecurityControl<Ath001Adapter, FindingKey> {
  constructor() {
    super({
      id: 'ATH-001',
      priority: 'HIGH',
      description: 'Athena workgroups must have query result encryption enabled using SSE_S3, SSE_KMS, or CSE_KMS, with a KMS key specified when SSE_KMS or CSE_KMS is used',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Ath001Adapter): FindingKey | null {
    if (adapter.isEncryptionUnknown()) return null;

    const encryptionFinding = this.evaluateEncryption(adapter);
    if (encryptionFinding) return encryptionFinding;

    return this.evaluateEnforcement(adapter);
  }

  private evaluateEncryption(adapter: Ath001Adapter): FindingKey | null {
    const option = adapter.getEncryptionOption();
    if (!option || !VALID_OPTIONS.includes(option)) return MISSING_ENCRYPTION;

    if (KMS_OPTIONS.includes(option) && !adapter.hasKmsKey()) return MISSING_KMS_KEY;

    return null;
  }

  private evaluateEnforcement(adapter: Ath001Adapter): FindingKey | null {
    if (adapter.isConfigurationEnforced() !== false) return null;
    return CONFIGURATION_NOT_ENFORCED;
  }
}

export const ath001Control = new Ath001Control();
