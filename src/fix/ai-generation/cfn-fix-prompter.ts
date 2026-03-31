import * as path from 'path';
import { sendPrompt } from '../../shared/ai/bedrock-client.js';
import { CloudFormationResourceParser } from '../../shared/project/cfn-resource-parser.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { Fix, FixChange } from '../types.js';

export class CfnFixPrompter {
    private readonly cfnParser = new CloudFormationResourceParser();

    public async generateFix(projectRootFolderPath: string, issue: ScanResult): Promise<Fix | null> {
        if (!issue.resourceName || !issue.path) {
            return null;
        }

        const templateFilePath = path.join(projectRootFolderPath, issue.path);
        const resource = await this.cfnParser.parseResourceFromTemplate(templateFilePath, issue.resourceName);

        if (!resource) {
            return null;
        }

        const ext = path.extname(templateFilePath).toLowerCase();
        const isYamlFile = ['.yaml', '.yml'].includes(ext);

        const formatSpecificInstructions = isYamlFile
            ? `CRITICAL YAML FORMATTING REQUIREMENTS:
- Preserve the EXACT indentation structure from the original resource
- The resource name should maintain its original indentation level (typically 2 spaces under "Resources:")
- All properties must maintain their relative indentation to the resource name
- Use spaces for indentation, not tabs
- Maintain the original line structure and spacing
- Do NOT remove or change the indentation of the resource name line`
            : `JSON formatting requirements:
- Maintain proper JSON syntax with correct bracket and brace placement
- Preserve the original indentation style`;

        const prompt = `Here is the full CloudFormation template for context:

<template>
${resource.fullTemplate}
</template>

<resource_details>
Resource Name: ${resource.resourceName}
Resource Type: ${resource.resourceType}
File Format: ${isYamlFile ? 'YAML' : 'JSON'}
</resource_details>

<issue>
${issue.issue}
</issue>

<fix>
${issue.fix}
</fix>

<instructions>
IMPORTANT: This issue applies ONLY to the resource specified in <resource_details>.

Return ALL CloudFormation resource changes needed to fix this issue. For EACH change:
- Wrap in <change> tags
- Include <original> with the EXACT resource definition AS IT CURRENTLY EXISTS in the template (copy verbatim)
- Include <updated> with your modified version of that same resource

CRITICAL: The <original> must be an exact substring that exists in the template. Do NOT put your fixed code in <original>.

${formatSpecificInstructions}

Example - if the template contains:
  MyMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      HttpMethod: GET
      RestApiId: !Ref MyApi

And you want to add RequestValidatorId, your change should be:
<change>
<original>  MyMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      HttpMethod: GET
      RestApiId: !Ref MyApi</original>
<updated>  MyMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      HttpMethod: GET
      RestApiId: !Ref MyApi
      RequestValidatorId: !Ref MyValidator</updated>
</change>

For NEW resources, find an insertion point and include surrounding context:
<change>
<original>  ExistingResource:
    Type: AWS::...

  NextResource:</original>
<updated>  ExistingResource:
    Type: AWS::...

  NewValidator:
    Type: AWS::ApiGateway::RequestValidator
    Properties:
      RestApiId: !Ref MyApi
      ValidateRequestBody: true

  NextResource:</updated>
</change>

Include any explanation in <comments> tags.
</instructions>`;

        const response = await sendPrompt(prompt);

        const changes = this.parseChanges(response, resource.fullTemplate, templateFilePath);

        if (changes.length === 0) {
            return null;
        }

        return {
            changes,
            comments: response.match(/<comments>([\s\S]*?)<\/comments>/)?.[1]?.trim() || ''
        };
    }

    private parseChanges(response: string, templateContent: string, filePath: string): FixChange[] {
        const changeMatches = response.matchAll(/<change>\s*<original>([\s\S]*?)<\/original>\s*<updated>([\s\S]*?)<\/updated>\s*<\/change>/g);

        const changes: FixChange[] = [];
        for (const match of changeMatches) {
            let original = match[1];
            let updated = match[2];

            // Only trim trailing whitespace, preserve leading indentation
            original = original.replace(/\s+$/, '').replace(/^[\r\n]+/, '');
            updated = updated.replace(/\s+$/, '').replace(/^[\r\n]+/, '');

            const lineNumber = original ? this.findLineNumber(templateContent, original) : templateContent.split('\n').length;

            changes.push({ filePath, original, updated, startingLineNumber: lineNumber });
        }
        return changes;
    }

    private findLineNumber(templateContent: string, searchText: string): number {
        // Normalize line endings for comparison
        const normalizedTemplate = templateContent.replace(/\r\n/g, '\n');
        const normalizedSearch = searchText.replace(/\r\n/g, '\n');

        const index = normalizedTemplate.indexOf(normalizedSearch);
        if (index === -1) {
            return 1;
        }
        return normalizedTemplate.substring(0, index).split('\n').length;
    }

}
