import * as fs from 'fs/promises';
import * as path from 'path';
import * as yamlcfn from "@aws-cdk/yaml-cfn";

export class CfnTemplateValidator {
    public async isCloudFormationTemplate(projectRootFolderPath: string, cloudformationTemplateFilePath: string): Promise<boolean> {
        const ext = path.extname(cloudformationTemplateFilePath).toLowerCase();

        try {
            const content = await fs.readFile(cloudformationTemplateFilePath, 'utf8');

            let parsed: any;
            if (['.yaml', '.yml'].includes(ext)) {
                parsed = yamlcfn.deserialize(content);
            } else if (ext === '.json') {
                parsed = JSON.parse(content);
            } else {
                return false;
            }

            if (!parsed || typeof parsed !== 'object') {
                return false;
            }

            const isValid = !!(parsed?.Resources && (
                parsed.AWSTemplateFormatVersion ||
                Object.values(parsed.Resources).some((r: any) =>
                    r?.Type && r.Type.startsWith('AWS::')
                )
            ));

            return isValid;

        } catch (error) {
            return false;
        }
    }
}
