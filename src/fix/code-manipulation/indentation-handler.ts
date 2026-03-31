export class IndentationHandler {
    public replaceWithIndentation(fileContent: string, originalCode: string, updatedCode: string): string {
        // Normalize line endings for matching
        const normalizedOriginal = originalCode.replace(/\r\n/g, '\n');
        const normalizedUpdated = updatedCode.replace(/\r\n/g, '\n');

        // Try to find with original line endings first
        let originalIndex = fileContent.indexOf(originalCode);

        // If not found, try normalized version
        if (originalIndex === -1) {
            const normalizedFile = fileContent.replace(/\r\n/g, '\n');
            originalIndex = normalizedFile.indexOf(normalizedOriginal);

            if (originalIndex === -1) {
                return fileContent;
            }

            // Work with normalized content
            return this.doReplace(normalizedFile, normalizedOriginal, normalizedUpdated, originalIndex);
        }

        return this.doReplace(fileContent, originalCode, updatedCode, originalIndex);
    }

    private doReplace(fileContent: string, originalCode: string, updatedCode: string, originalIndex: number): string {
        const beforeOriginal = fileContent.substring(0, originalIndex);
        const lineStartIndex = beforeOriginal.lastIndexOf('\n') + 1;
        const indentation = fileContent.substring(lineStartIndex, originalIndex);

        const updatedLines = updatedCode.split('\n');
        const indentedUpdatedCode = updatedLines
            .map((line, index) => {
                // Don't add indentation to empty lines or the first line (it already has proper positioning)
                if (line.trim() === '') return line;
                if (index === 0) return line;
                return indentation + line;
            })
            .join('\n');

        return fileContent.substring(0, originalIndex) +
            indentedUpdatedCode +
            fileContent.substring(originalIndex + originalCode.length);
    }
}
