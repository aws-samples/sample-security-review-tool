import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { Ath001Adapter } from './ath-001.adapter.js';

export class Ath001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_athena_workgroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Ath001TfAdapter {
    return new Ath001TfAdapter(context);
  }
}

type Values = Record<string, unknown>;

const ENCRYPTION_OPTION = 'encryption_option';
const KMS_KEY = 'kms_key_arn';
const ENFORCE_CONFIGURATION = 'enforce_workgroup_configuration';

/** Terraform blocks are represented as single-element arrays in plan values. */
function unwrap(value: unknown): unknown {
  return Array.isArray(value) ? value[0] : value;
}

function asValues(value: unknown): Values | undefined {
  const candidate = unwrap(value);
  return candidate !== null && typeof candidate === 'object' && !Array.isArray(candidate) ? (candidate as Values) : undefined;
}

/** A nested block that is present but null could not be resolved at plan time. */
function isBlockUnknown(parent: Values | undefined, name: string): boolean {
  if (!parent || !(name in parent)) return false;
  return unwrap(parent[name]) === null;
}

/** An attribute recorded as null was written in the configuration but unknown at plan time. */
function isAttributeUnknown(block: Values, name: string): boolean {
  return name in block && block[name] === null;
}

/**
 * Every encryption attribute being null means the block was cleared, not that a value is
 * pending resolution, so such a block is treated as known-empty rather than unknown.
 */
function isBlockCleared(block: Values): boolean {
  return isAttributeUnknown(block, ENCRYPTION_OPTION) && isAttributeUnknown(block, KMS_KEY);
}

function isEncryptionValueUnknown(block: Values | undefined): boolean {
  if (!block || isBlockCleared(block)) return false;
  return isAttributeUnknown(block, ENCRYPTION_OPTION) || isAttributeUnknown(block, KMS_KEY);
}

class Ath001TfAdapter implements Ath001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  getEncryptionOption(): string | undefined {
    const option = this.encryptionConfiguration()?.[ENCRYPTION_OPTION];
    return typeof option === 'string' ? option : undefined;
  }

  hasKmsKey(): boolean {
    const key = this.encryptionConfiguration()?.[KMS_KEY];
    if (typeof key === 'string') return key.trim().length > 0;
    return key !== undefined && key !== null;
  }

  isEncryptionUnknown(): boolean {
    const values = this.values();
    if (isBlockUnknown(values, 'configuration')) return true;

    const configuration = asValues(values['configuration']);
    if (isBlockUnknown(configuration, 'result_configuration')) return true;

    const resultConfiguration = asValues(configuration?.['result_configuration']);
    if (isBlockUnknown(resultConfiguration, 'encryption_configuration')) return true;

    return isEncryptionValueUnknown(asValues(resultConfiguration?.['encryption_configuration']));
  }

  /** Terraform defaults this setting to true when it is not written in the configuration. */
  isConfigurationEnforced(): boolean | undefined {
    const values = this.values();
    if (isBlockUnknown(values, 'configuration')) return undefined;

    const configuration = asValues(values['configuration']);
    if (!configuration || !(ENFORCE_CONFIGURATION in configuration)) return true;

    const enforce = configuration[ENFORCE_CONFIGURATION];
    if (enforce === null) return undefined;
    return typeof enforce === 'boolean' ? enforce : true;
  }

  private values(): Values {
    return (this.ctx.resource.values ?? {}) as Values;
  }

  private encryptionConfiguration(): Values | undefined {
    const configuration = asValues(this.values()['configuration']);
    const resultConfiguration = asValues(configuration?.['result_configuration']);
    return asValues(resultConfiguration?.['encryption_configuration']);
  }
}
