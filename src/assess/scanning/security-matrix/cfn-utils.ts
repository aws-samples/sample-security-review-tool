// CloudFormation template parsing utilities
// Inspired by cloudformation-typescript-parser project

import { Template } from 'cloudform-types';
import { yamlParse } from 'yaml-cfn';
import * as fs from 'fs';
import { promisify } from 'util';
import * as path from 'path';
import { findAndReplaceIf } from "find-and-replace-anything";

export const readCfnFile = async (filePath: string): Promise<Template> => {
  return new CfnFileContext(filePath).read();
};

class CfnFileContext {
  private reader: CfnFileReader;

  constructor(protected filePath: string) {
    switch (path.extname(filePath)) {
      case '.yaml':
      case '.yml':
        this.reader = new CfnYamlReader(filePath);
        break;
      case '.json':
        this.reader = new CfnJsonReader(filePath);
        break;
      default:
        throw new Error(
          'unsupported file extension. Supported file extensions: .json, .yaml, .yml',
        );
    }
  }

  async read(): Promise<Template> {
    return this.reader.read();
  }
}

abstract class CfnFileReader {
  constructor(protected filePath: string) {}
  abstract read(): Promise<Template>;
}

class CfnYamlReader extends CfnFileReader {
  constructor(protected filePath: string) {
    super(filePath);
  }
  async read() {
    const templateFile = await promisify(fs.readFile)(this.filePath, 'utf-8');
    return yamlParse(templateFile);
  }
}

class CfnJsonReader extends CfnFileReader {
  constructor(protected filePath: string) {
    super(filePath);
  }
  async read() {
    const templateFile = await promisify(fs.readFile)(this.filePath, 'utf-8');
    return JSON.parse(templateFile) as Template;
  }
}

export const parseCfnTemplate = (template: Template): Template => {
    const region = "us-east-1";
    const accountId = "123456789012";
    const partition = "aws";
    const urlSuffix = "amazonaws.com";
    const stackName = "test-stack";

    function filterRef(val: any) {
        if (val && val.hasOwnProperty("Ref")) {
            const refValue = val.Ref;

            // Handle AWS pseudo-parameters
            const pseudoParams: { [key: string]: any } = {
                'AWS::AccountId': accountId,
                'AWS::Region': region,
                'AWS::Partition': partition,
                'AWS::URLSuffix': urlSuffix,
                'AWS::StackName': stackName,
                'AWS::StackId': `arn:${partition}:cloudformation:${region}:${accountId}:stack/${stackName}/00000000-0000-0000-0000-000000000000`,
                'AWS::NotificationARNs': [],
                'AWS::NoValue': undefined
            };

            if (refValue in pseudoParams) {
                return pseudoParams[refValue];
            }

            // Check Parameters
            if (template.Parameters && refValue in template.Parameters) {
                return template.Parameters[refValue].Default || "DEFAULT";
            }

            // Check Resources - return the logical resource ID
            if (template.Resources && refValue in template.Resources) {
                return refValue;
            }

            // Fallback
            return "DEFAULT";
        }
        return val;
    }

    function filterParams(val: any) {
        if (typeof val === "string") {
            if (template.Parameters) {
                Object.keys(template.Parameters).forEach((key) => {
                    const value = template.Parameters![key].Default || "DEFAULT";
                    if (typeof val === "string") {
                        val = val.replace("${" + key + "}", value);
                    }
                });
            }
        }
        return val;
    }

    function filterSub(val: any) {
        if (val && val.hasOwnProperty("Fn::Sub")) {
            if (Array.isArray(val["Fn::Sub"])) {
                const props = val["Fn::Sub"][1];
                const key = Object.keys(props)[0];
                let value = props[key];
                value = replaceRecursively(value);
                val["Fn::Sub"][0] = val["Fn::Sub"][0].replace("${" + key + "}", value);

                return findAndReplaceIf(val["Fn::Sub"][0], filterParams);
            }

            let result = val["Fn::Sub"];

            // Replace Parameters if they exist
            if (template.Parameters) {
                Object.keys(template.Parameters).forEach((key) => {
                    const value = template.Parameters![key].Default || "DEFAULT";
                    if (typeof result === "string") {
                        result = result.replace("${" + key + "}", value);
                    }
                });
            }

            // Replace AWS pseudo-parameters
            if (typeof result === "string") {
                result = result.replace(/\$\{AWS::Region\}/g, region);
                result = result.replace(/\$\{AWS::AccountId\}/g, accountId);
                result = result.replace(/\$\{AWS::Partition\}/g, partition);
                result = result.replace(/\$\{AWS::URLSuffix\}/g, urlSuffix);
                result = result.replace(/\$\{AWS::StackName\}/g, stackName);
                result = result.replace(/\$\{AWS::StackId\}/g, `arn:${partition}:cloudformation:${region}:${accountId}:stack/${stackName}/00000000-0000-0000-0000-000000000000`);

                // Clean up any remaining ${} patterns (fallback)
                result = result.replace(/\$\{/g, "");
                result = result.replace(/\}/g, "");
            }
            return result;
        }

        return val;
    }

    function filterFindInMap(val: any) {
        if (val && val.hasOwnProperty("Fn::FindInMap")) {
            const [mapping, key, name] = val["Fn::FindInMap"].map((item: any) =>
                replaceRecursively(item)
            );

            return template.Mappings![mapping][key][name];
        }

        return val;
    }

    function arrayProps(foundVal: any) {
        if (Array.isArray(foundVal)) {
            return foundVal.map((item) => replaceRecursively(item));
        }
        return foundVal;
    }

    function replaceRecursively(val: any) {
        val = findAndReplaceIf(val, filterRef);
        val = findAndReplaceIf(val, filterSub);
        val = findAndReplaceIf(val, filterFindInMap);
        val = findAndReplaceIf(val, arrayProps);
        return val;
    }

    return replaceRecursively(template);
};
