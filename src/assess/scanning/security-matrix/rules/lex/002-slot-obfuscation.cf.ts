import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

export class Lex002Rule extends BaseRule {
    constructor() {
        super(
            'LEX-002',
            'HIGH',
            'Amazon Lex V2 bot contains slots with obfuscation explicitly disabled',
            ['AWS::Lex::Bot']
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const resolver = new CloudFormationResolver(allResources);
        const disabledSlots = this.findSlotsWithDisabledObfuscation(resource.Properties, resolver);

        if (disabledSlots.length > 0) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}. Found ${disabledSlots.length} slot(s) with obfuscation explicitly disabled: ${disabledSlots.join(', ')}`,
                `Remove ObfuscationSetting property or set ObfuscationSettingType to 'DefaultObfuscation'.`
            );
        }

        return null;
    }

    private findSlotsWithDisabledObfuscation(properties: any, resolver: CloudFormationResolver): string[] {
        const disabledSlots: string[] = [];

        try {
            const botLocales = resolver.resolve(properties?.BotLocales);

            if (!botLocales.isResolved || !Array.isArray(botLocales.value)) return disabledSlots;

            botLocales.value.forEach((locale: any) => {
                const intents = resolver.resolve(locale?.Intents);
                if (!intents.isResolved || !Array.isArray(intents.value)) return;

                intents.value.forEach((intent: any) => {
                    const slots = resolver.resolve(intent?.Slots);
                    if (!slots.isResolved || !Array.isArray(slots.value)) return;

                    slots.value.forEach((slot: any) => {
                        const obfuscationSetting = resolver.resolve(slot?.ObfuscationSetting);
                        if (!obfuscationSetting.isResolved) return;

                        const obfuscationType = resolver.resolve(obfuscationSetting.value?.ObfuscationSettingType);
                        if (obfuscationType.isResolved && obfuscationType.value === 'None') {
                            const slotName = resolver.resolve(slot?.Name);
                            const name = slotName.isResolved ? slotName.value : 'unnamed slot';
                            disabledSlots.push(name);
                        }
                    });
                });
            });
        } catch (error) {
            // If we can't parse the structure, assume it's safe rather than erroring
        }

        return disabledSlots;
    }
}

export default new Lex002Rule();