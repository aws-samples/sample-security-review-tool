import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { isObfuscationDisabledType, Lex002Adapter } from './lex-002.adapter.js';

export class Lex002CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::Lex::Bot'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Lex002CfnAdapter {
    return new Lex002CfnAdapter(context);
  }
}

type Props = Record<string, unknown>;

class Lex002CfnAdapter implements Lex002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  findSlotsWithoutObfuscation(): string[] {
    return this.slots().filter(slot => this.isObfuscationDisabled(slot)).map(slot => this.slotName(slot));
  }

  private slots(): Props[] {
    const properties = this.ctx.resource.Properties as Props | undefined;
    return this.asArray(properties?.['BotLocales'])
      .flatMap(locale => this.asArray(locale['Intents']))
      .flatMap(intent => this.asArray(intent['Slots']));
  }

  private isObfuscationDisabled(slot: Props): boolean {
    const setting = slot['ObfuscationSetting'];
    if (setting === undefined || setting === null) return true;
    if (!this.isRecord(setting)) return false;
    return isObfuscationDisabledType(setting['ObfuscationSettingType']);
  }

  private slotName(slot: Props): string {
    const name = slot['Name'];
    return typeof name === 'string' ? name : 'unnamed slot';
  }

  private asArray(value: unknown): Props[] {
    return Array.isArray(value) ? value.filter(item => this.isRecord(item)) : [];
  }

  private isRecord(value: unknown): value is Props {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
