import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Ath001Adapter } from './ath-001.adapter.js';

export class Ath001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::Athena::WorkGroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Ath001CfnAdapter {
    return new Ath001CfnAdapter(context);
  }
}

type Props = Record<string, unknown>;

const ENFORCE_CONFIGURATION = 'EnforceWorkGroupConfiguration';

function asRecord(value: unknown): Props | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Props) : undefined;
}

function isUnresolvedIntrinsic(value: unknown): boolean {
  const record = asRecord(value);
  if (!record) return false;
  return Object.keys(record).some(key => key === 'Fn::If' || key === 'Fn::ImportValue' || key === 'Fn::Select' || key === 'Fn::Join');
}

/** CloudFormation accepts booleans as literals or as their string equivalents. */
function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

class Ath001CfnAdapter implements Ath001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  getEncryptionOption(): string | undefined {
    const option = this.encryptionConfiguration()?.['EncryptionOption'];
    return typeof option === 'string' ? option : undefined;
  }

  hasKmsKey(): boolean {
    const key = this.encryptionConfiguration()?.['KmsKey'];
    if (typeof key === 'string') return key.trim().length > 0;
    return key !== undefined && key !== null;
  }

  isEncryptionUnknown(): boolean {
    const configuration = this.workGroupConfigurationValue();
    if (isUnresolvedIntrinsic(configuration)) return true;

    const resultConfiguration = asRecord(configuration)?.['ResultConfiguration'];
    if (isUnresolvedIntrinsic(resultConfiguration)) return true;

    const encryption = asRecord(resultConfiguration)?.['EncryptionConfiguration'];
    if (isUnresolvedIntrinsic(encryption)) return true;

    return isUnresolvedIntrinsic(asRecord(encryption)?.['EncryptionOption']);
  }

  isConfigurationEnforced(): boolean | undefined {
    const configuration = this.workGroupConfigurationValue();
    if (isUnresolvedIntrinsic(configuration)) return undefined;

    const enforce = asRecord(configuration)?.[ENFORCE_CONFIGURATION];
    if (isUnresolvedIntrinsic(enforce)) return undefined;
    if (enforce === undefined || enforce === null) return true;
    return asBoolean(enforce);
  }

  private workGroupConfigurationValue(): unknown {
    return asRecord(this.ctx.resource.Properties)?.['WorkGroupConfiguration'];
  }

  private encryptionConfiguration(): Props | undefined {
    const configuration = asRecord(this.workGroupConfigurationValue());
    const resultConfiguration = asRecord(configuration?.['ResultConfiguration']);
    return asRecord(resultConfiguration?.['EncryptionConfiguration']);
  }
}
