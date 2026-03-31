export interface CdkFile {
    file: string;
    language: 'typescript' | 'python';
}

export class CdkCommandParser {
    public extractFromCdkJson(cdkJsonContent: string): CdkFile | null {
        try {
            const cdkConfig = JSON.parse(cdkJsonContent);
            const appCommand = cdkConfig.app;

            if (!appCommand) return null;

            return this.extractFile(appCommand);
        } catch (error) {
            console.error('Error parsing cdk.json:', error);
            return null;
        }
    }

    private extractFile(appCommand: string): CdkFile | null {
        // Try TypeScript first
        const tsFile = this.extractTypeScriptFile(appCommand);
        if (tsFile) {
            return { file: tsFile, language: 'typescript' };
        }

        // Try Python if TypeScript didn't match
        const pyFile = this.extractPythonFile(appCommand);
        if (pyFile) {
            return { file: pyFile, language: 'python' };
        }

        return null;
    }

    private extractTypeScriptFile(appCommand: string): string | null {
        if (!appCommand || typeof appCommand !== 'string') return null;

        // Split the command into parts, handling quoted arguments
        const parts = this.parseCommandLine(appCommand);

        // Find ts-node in the command
        const tsNodeIndex = parts.findIndex(part =>
            part === 'ts-node' || part.endsWith('/ts-node') || part === 'npx'
        );

        if (tsNodeIndex === -1) return null;

        // Start looking for the TypeScript file after ts-node
        let startIndex = tsNodeIndex + 1;

        // If we found 'npx', look for 'ts-node' next
        if (parts[tsNodeIndex] === 'npx') {
            const actualTsNodeIndex = parts.findIndex((part, index) =>
                index > tsNodeIndex && (part === 'ts-node' || part.endsWith('/ts-node'))
            );

            if (actualTsNodeIndex !== -1) startIndex = actualTsNodeIndex + 1;
        }

        // Skip over ts-node flags and their values
        for (let i = startIndex; i < parts.length; i++) {
            const part = parts[i];

            // Skip flags that take values
            if (part === '-P' || part === '--project' ||
                part === '-T' || part === '--transpiler' ||
                part === '--compiler-options') {
                i++; // Skip the next part (the flag's value)
                continue;
            }

            // Skip boolean flags
            if (part.startsWith('-')) {
                continue;
            }

            // This should be our TypeScript file
            if (part.endsWith('.ts') || part.endsWith('.tsx')) {
                return part;
            }

            // If we hit a non-flag that doesn't end in .ts/.tsx, it's probably not our file
            return null;
        }

        return null;
    }

    private extractPythonFile(appCommand: string): string | null {
        if (!appCommand || typeof appCommand !== 'string') return null;

        // Split the command into parts, handling quoted arguments
        const parts = this.parseCommandLine(appCommand);

        // Find Python interpreter in the command
        const pythonIndex = parts.findIndex(part =>
            part === 'python' || part === 'python3' || part === 'python2' ||
            part.endsWith('/python') || part.endsWith('/python3') || part.endsWith('/python2') ||
            part.endsWith('\\python.exe') || part.endsWith('\\python3.exe')
        );

        if (pythonIndex === -1) return null;

        // Start looking for the Python file after python interpreter
        let startIndex = pythonIndex + 1;

        // Skip over Python flags and their values
        for (let i = startIndex; i < parts.length; i++) {
            const part = parts[i];

            // Skip flags that take values
            if (part === '-m' || part === '--module' ||
                part === '-c' || part === '--command' ||
                part === '-W' || part === '--warning' ||
                part === '-X' || part === '--dev') {
                // For -m, the next part is the module name, not a file
                if (part === '-m' || part === '--module') {
                    i++; // Skip the module name
                    const moduleName = parts[i];
                    if (moduleName) {
                        // Convert module name to file path (e.g., "app" -> "app.py")
                        return moduleName.includes('.') ?
                            moduleName.replace(/\./g, '/') + '.py' :
                            moduleName + '.py';
                    }
                } else {
                    i++; // Skip the flag's value
                }
                continue;
            }

            // Skip boolean flags
            if (part.startsWith('-')) {
                continue;
            }

            // This should be our Python file
            if (part.endsWith('.py') || part.endsWith('.pyw')) {
                return part;
            }

            // If we hit a non-flag that doesn't end in .py/.pyw, it might be a module or script
            // For Python, sometimes people run without .py extension
            if (!part.includes('/') && !part.includes('\\') && !part.includes('.')) {
                // Likely a module name, assume .py extension
                return part + '.py';
            }

            // If it has a path but no extension, assume .py
            if ((part.includes('/') || part.includes('\\')) && !part.includes('.')) {
                return part + '.py';
            }

            // Return as-is if it looks like a file path
            return part;
        }

        return null;
    }

    private parseCommandLine(command: string): string[] {
        const parts: string[] = [];
        let current = '';
        let inQuotes = false;
        let quoteChar = '';

        for (let i = 0; i < command.length; i++) {
            const char = command[i];

            if (!inQuotes && (char === '"' || char === "'")) {
                inQuotes = true;
                quoteChar = char;
            } else if (inQuotes && char === quoteChar) {
                inQuotes = false;
                quoteChar = '';
            } else if (!inQuotes && /\s/.test(char)) {
                if (current.trim()) {
                    parts.push(current.trim());
                    current = '';
                }
            } else {
                current += char;
            }
        }

        if (current.trim()) {
            parts.push(current.trim());
        }

        return parts;
    }

    // Convenience methods for backward compatibility and specific use cases
    public extractTypeScriptFileOnly(cdkJsonContent: string): string | null {
        const result = this.extractFromCdkJson(cdkJsonContent);
        return result?.language === 'typescript' ? result.file : null;
    }

    public extractPythonFileOnly(cdkJsonContent: string): string | null {
        const result = this.extractFromCdkJson(cdkJsonContent);
        return result?.language === 'python' ? result.file : null;
    }
}
