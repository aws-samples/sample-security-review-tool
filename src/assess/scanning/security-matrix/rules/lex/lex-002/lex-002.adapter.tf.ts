import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { isObfuscationDisabledType, Lex002Adapter } from './lex-002.adapter.js';

export class Lex002TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_lexv2models_slot'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Lex002TfAdapter {
    return new Lex002TfAdapter(context);
  }
}

type Values = Record<string, unknown>;

class Lex002TfAdapter implements Lex002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  findSlotsWithoutObfuscation(): string[] {
    return this.isObfuscationDisabled() ? [this.slotName()] : [];
  }

  private isObfuscationDisabled(): boolean {
    const settings = this.obfuscationSettings();
    if (settings.length === 0) return this.isObfuscationUnconfigured();
    return settings.some(setting => isObfuscationDisabledType(setting['obfuscation_setting_type']));
  }

  private isObfuscationUnconfigured(): boolean {
    const setting = this.values()['obfuscation_setting'];
    return setting === undefined || setting === null || (Array.isArray(setting) && setting.length === 0);
  }

  private obfuscationSettings(): Values[] {
    const setting = this.values()['obfuscation_setting'];
    if (Array.isArray(setting)) return setting.filter(item => this.isRecord(item));
    return this.isRecord(setting) ? [setting] : [];
  }

  private slotName(): string {
    const name = this.values()['name'];
    return typeof name === 'string' ? name : this.resourceId;
  }

  private values(): Values {
    const values = this.ctx.resource.values as Values | undefined;
    return values ?? {};
  }

  private isRecord(value: unknown): value is Values {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
