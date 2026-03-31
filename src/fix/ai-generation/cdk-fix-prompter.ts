import { sendPrompt } from '../../shared/ai/bedrock-client.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { CdkConstructInfo } from '../cdk/cdk-construct-resolver.js';
import { Fix, FixChange } from '../types.js';

export class CdkFixPrompter {
    public async generateFix(cdkConstruct: CdkConstructInfo, issue: ScanResult): Promise<Fix | null> {
        const prompt = `Here is the full file for context:

<file>
${cdkConstruct.context}
</file>

<resource_details>
Resource Name: ${issue.resourceName}
Resource Type: ${issue.resourceType}
CDK Construct Path: ${issue.cdkPath}
</resource_details>

<issue>
${issue.issue}
</issue>

<fix>
${issue.fix}
</fix>

<instructions>
IMPORTANT: This issue applies ONLY to the resource specified in <resource_details>.

Return ALL code changes needed to fix this issue. For EACH change:
- Wrap in <change> tags
- Include <original> with the EXACT code AS IT CURRENTLY EXISTS in the file (copy verbatim from the file above)
- Include <updated> with your modified version of that same code

CRITICAL: The <original> must be an exact substring that exists in the file. Do NOT put your fixed code in <original>.

Example - if the file contains:
  healthResource.addMethod('GET', integration);

And you want to add requestValidator, your change should be:
<change>
<original>healthResource.addMethod('GET', integration);</original>
<updated>healthResource.addMethod('GET', integration, {
  requestValidator: requestValidator,
});</updated>
</change>

For NEW code (like creating a RequestValidator), find an insertion point and include enough surrounding context:
<change>
<original>const api = new RestApi(this, 'MyApi', { ... });

// Next line of code</original>
<updated>const api = new RestApi(this, 'MyApi', { ... });

const requestValidator = new RequestValidator(this, 'Validator', {
  restApi: api,
  validateRequestBody: true,
});

// Next line of code</updated>
</change>

Include any explanation in <comments> tags.
</instructions>`;

        const response = await sendPrompt(prompt);

        const changes = this.parseChanges(response, cdkConstruct.context, cdkConstruct.filePath);

        if (changes.length === 0) {
            return null;
        }

        return {
            changes,
            comments: response.match(/<comments>([\s\S]*?)<\/comments>/)?.[1]?.trim() || ''
        };
    }

    private parseChanges(response: string, fileContent: string, filePath: string): FixChange[] {
        const changeMatches = response.matchAll(/<change>\s*<original>([\s\S]*?)<\/original>\s*<updated>([\s\S]*?)<\/updated>\s*<\/change>/g);

        const changes: FixChange[] = [];
        for (const match of changeMatches) {
            // Only trim trailing whitespace and leading newlines, preserve indentation
            // Normalize line endings to LF
            let original = match[1].replace(/\r\n/g, '\n').replace(/\s+$/, '').replace(/^[\r\n]+/, '');
            let updated = match[2].replace(/\r\n/g, '\n').replace(/\s+$/, '').replace(/^[\r\n]+/, '');

            const lineNumber = original ? this.findLineNumber(fileContent, original) : fileContent.split('\n').length;

            changes.push({ filePath, original, updated, startingLineNumber: lineNumber });
        }
        return changes;
    }

    private findLineNumber(fileContent: string, searchText: string): number {
        // Normalize line endings for comparison
        const normalizedFile = fileContent.replace(/\r\n/g, '\n');
        const normalizedSearch = searchText.replace(/\r\n/g, '\n');

        const index = normalizedFile.indexOf(normalizedSearch);
        if (index === -1) {
            return 1;
        }
        return normalizedFile.substring(0, index).split('\n').length;
    }

}
