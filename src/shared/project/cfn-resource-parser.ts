import * as fs from 'fs';
import * as path from 'path';
import * as yamlcfn from "@aws-cdk/yaml-cfn";

export interface CloudFormationResource {
    resourceName: string;
    resourceType: string;
    resourceContent: string;
    startLine: number;
    endLine: number;
    fullTemplate: string;
}

export class CloudFormationResourceParser {

    public async parseResourceFromTemplate(
        templateFilePath: string,
        resourceName: string
    ): Promise<CloudFormationResource | null> {
        try {
            const templateContent = await fs.promises.readFile(templateFilePath, 'utf-8');
            const ext = path.extname(templateFilePath).toLowerCase();

            let parsed: any;
            if (['.yaml', '.yml'].includes(ext)) {
                parsed = yamlcfn.deserialize(templateContent);
            } else if (ext === '.json') {
                parsed = JSON.parse(templateContent);
            } else {
                return null;
            }

            if (!parsed?.Resources || !parsed.Resources[resourceName]) {
                return null;
            }

            const resource = parsed.Resources[resourceName];
            const resourceType = resource.Type;

            // Find the line numbers for this resource in the original file
            const { startLine, endLine } = this.findResourceLines(templateContent, resourceName, ext);

            // Extract just the resource content
            const resourceContent = this.extractResourceContent(templateContent, resourceName, startLine, endLine);

            return {
                resourceName,
                resourceType,
                resourceContent,
                startLine,
                endLine,
                fullTemplate: templateContent
            };

        } catch (error) {
            return null;
        }
    }

    private findResourceLines(templateContent: string, resourceName: string, fileExtension: string): { startLine: number, endLine: number } {
        const lines = templateContent.split('\n');
        let startLine = -1;
        let endLine = -1;

        // Look for the resource declaration
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            if (fileExtension === '.json') {
                // For JSON, look for "ResourceName": {
                if (line.includes(`"${resourceName}":`)) {
                    startLine = i + 1; // 1-based line numbers
                    // Find the closing brace for this resource
                    let braceCount = 0;
                    let foundOpenBrace = false;
                    for (let j = i; j < lines.length; j++) {
                        const currentLine = lines[j];
                        for (const char of currentLine) {
                            if (char === '{') {
                                braceCount++;
                                foundOpenBrace = true;
                            } else if (char === '}') {
                                braceCount--;
                                if (foundOpenBrace && braceCount === 0) {
                                    endLine = j + 1;
                                    return { startLine, endLine };
                                }
                            }
                        }
                    }
                    break;
                }
            } else {
                // For YAML, look for ResourceName: (at the beginning of a line or after whitespace)
                if (line === `${resourceName}:` || line.match(new RegExp(`^\\s*${resourceName}:\\s*$`))) {
                    startLine = i + 1;

                    // Find the indentation level
                    const indentMatch = lines[i].match(/^(\s*)/);
                    const baseIndent = indentMatch ? indentMatch[1].length : 0;

                    // Find the end of this resource (next resource at same or lower indentation)
                    for (let j = i + 1; j < lines.length; j++) {
                        const currentLine = lines[j];
                        if (currentLine.trim() === '') continue; // Skip empty lines

                        const currentIndentMatch = currentLine.match(/^(\s*)/);
                        const currentIndent = currentIndentMatch ? currentIndentMatch[1].length : 0;

                        // If we find a line at the same or lower indentation level, we've found the end
                        if (currentIndent <= baseIndent && currentLine.trim() !== '') {
                            endLine = j;
                            return { startLine, endLine };
                        }
                    }

                    // If we reach here, the resource goes to the end of the file
                    endLine = lines.length;
                    return { startLine, endLine };
                }
            }
        }

        // Fallback: return the whole file if we can't find specific boundaries
        return { startLine: 1, endLine: lines.length };
    }

    private extractResourceContent(templateContent: string, resourceName: string, startLine: number, endLine: number): string {
        const lines = templateContent.split('\n');
        const resourceLines = lines.slice(startLine - 1, endLine);
        return resourceLines.join('\n');
    }
}
