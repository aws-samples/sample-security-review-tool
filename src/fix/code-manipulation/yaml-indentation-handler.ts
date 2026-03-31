import * as path from 'path';
import { IndentationHandler } from './indentation-handler.js';

export class YamlIndentationHandler {
    private readonly indentationHandler = new IndentationHandler();

    public replaceCloudFormationResource(
        fileContent: string,
        originalCode: string,
        updatedCode: string,
        filePath: string
    ): string {
        const originalIndex = fileContent.indexOf(originalCode);
        if (originalIndex === -1) return fileContent; // Return unchanged if original code not found

        // Detect file type for proper handling
        const ext = path.extname(filePath).toLowerCase();
        const isYamlFile = ['.yaml', '.yml'].includes(ext);

        if (!isYamlFile) {
            // For JSON files, use the standard indentation logic
            return this.indentationHandler.replaceWithIndentation(fileContent, originalCode, updatedCode);
        }

        // Split both original and updated code into lines
        const originalLines = originalCode.split('\n');
        const updatedLines = updatedCode.split('\n');

        // Check if the AI response already has any indentation on the first line
        const updatedResourceLine = updatedLines[0];
        const updatedIndentMatch = updatedResourceLine.match(/^(\s*)/);
        const updatedResourceIndentation = updatedIndentMatch ? updatedIndentMatch[1] : '';

        // If the AI response already has indentation, use it as-is
        if (updatedResourceIndentation.length > 0) {
            return fileContent.substring(0, originalIndex) +
                updatedCode +
                fileContent.substring(originalIndex + originalCode.length);
        }

        // If the AI response has no indentation, map each line to its corresponding original indentation
        // Create a map of line content to indentation from the original
        const originalIndentMap = new Map<string, string>();
        originalLines.forEach(line => {
            const trimmedLine = line.trim();
            if (trimmedLine !== '') {
                const indentMatch = line.match(/^(\s*)/);
                const indent = indentMatch ? indentMatch[1] : '';
                originalIndentMap.set(trimmedLine, indent);
            }
        });

        // Apply indentation to updated code
        const indentedUpdatedCode = updatedLines
            .map((line, index) => {
                const trimmedLine = line.trim();
                if (trimmedLine === '') return line; // Keep empty lines as-is

                // Try to find matching indentation from original
                if (originalIndentMap.has(trimmedLine)) {
                    const originalIndent = originalIndentMap.get(trimmedLine)!;
                    return originalIndent + trimmedLine;
                }

                // If no exact match, use position-based indentation
                if (index < originalLines.length) {
                    const originalLine = originalLines[index];
                    const originalIndentMatch = originalLine.match(/^(\s*)/);
                    const originalIndent = originalIndentMatch ? originalIndentMatch[1] : '';
                    return originalIndent + trimmedLine;
                }

                // Fallback: use resource-level indentation + 2 spaces for new lines
                const originalResourceIndent = originalLines[0].match(/^(\s*)/)?.[1] || '';
                const fallbackIndent = originalResourceIndent + '  ';
                return fallbackIndent + trimmedLine;
            })
            .join('\n');

        return fileContent.substring(0, originalIndex) +
            indentedUpdatedCode +
            fileContent.substring(originalIndex + originalCode.length);
    }
}
