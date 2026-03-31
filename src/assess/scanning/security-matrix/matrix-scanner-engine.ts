import * as path from 'path';
import { CloudFormationResource, BaseRule } from './security-rule-base.js';
import { allRules } from './rules/index.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { ScanResult } from '../base-scanner.js';
import { readCfnFile, parseCfnTemplate } from './cfn-utils.js';
import { Template } from 'cloudform-types';
import { ScannerUtils } from '../utils/scanner-utils.js';

export class SecurityMatrixScannerEngine {
  private rules: BaseRule[] = [...allRules];

  public async run(projectRootFolderPath: string, templateFilePath: string, outputFilePath: string): Promise<boolean> {
    try {
      const template = await readCfnFile(templateFilePath);
      const parsedTemplate = parseCfnTemplate(template);

      if (!parsedTemplate || !parsedTemplate.Resources) {
        SrtLogger.logError('Invalid CloudFormation template', new Error(templateFilePath));
        return false;
      }

      const templateRelativeFilePath = path.relative(projectRootFolderPath, templateFilePath);
      const results = this.evaluate(parsedTemplate, templateRelativeFilePath);

      await ScannerUtils.ensureDirectoryExists(path.dirname(outputFilePath));
      await ScannerUtils.writeJsonFile(outputFilePath, results);

      return true;
    } catch (error) {
      SrtLogger.logError('Error scanning CloudFormation template', error as Error);
      return false;
    }
  }

  private evaluate(template: Template, stackName: string): ScanResult[] {
    const results: ScanResult[] = [];

    for (const resourceId in template.Resources) {
      const resource = template.Resources[resourceId];

      const applicableRules = this.rules
        .filter(rule => rule.appliesTo(resource.Type))
        .sort((a, b) => a.id.localeCompare(b.id));

      for (const rule of applicableRules) {
        try {
          // evaluateResource is the new implementation method that enables simpler rule evaluation
          // If it returns undefined, we fall back to the old evaluate method for backward compatibility
          let result = rule.evaluateResource(stackName, template, resource);

          if (result === undefined) {
            const cfResources = Object.entries(template.Resources).map(
              ([logicalId, res]: [string, any]) => ({
                Type: res.Type,
                Properties: res.Properties || {},
                LogicalId: logicalId
              }));
            const cfResource: CloudFormationResource = {
              Type: resource.Type,
              Properties: resource.Properties || {},
              LogicalId: resourceId,
              Metadata: resource.Metadata
            };

            // Fallback to the old evaluate method for backward compatibility
            result = rule.evaluate(cfResource, stackName, cfResources);
          }

          if (result) {
            results.push(result);
          }
        } catch (error) {
          SrtLogger.logError(`Error evaluating rule ${rule.id} for resource ${resourceId}`, error as Error);
        }
      }
    }

    return results;
  }
}
