import * as ts from 'typescript';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface ConstructInfo {
    code: string;
    lineNumber: number;
    filePath: string;
    fileContent: string;
    isImported: boolean;
    context?: string;
}

export class CdkConstructFinder {
    public async findConstructCode(stackContent: string, cdkPath: string, stackFilePath: string): Promise<ConstructInfo | null> {
        const pathParts = cdkPath.split('/');
        if (pathParts.length < 2) {
            return null;
        }

        const stackName = pathParts[0];
        const topLevelConstructId = pathParts[1];
        const targetConstructId = pathParts.length > 2 ? pathParts[2] : topLevelConstructId;

        const sourceFile = ts.createSourceFile(
            'stack.ts',
            stackContent,
            ts.ScriptTarget.Latest,
            true
        );

        // First, find the top-level construct in the stack
        const topLevelResult = this.findMatchingConstruct(sourceFile, topLevelConstructId);
        if (!topLevelResult) {
            return null;
        }

        // Check if the top-level construct is imported from a local file
        const importInfo = this.findConstructImport(sourceFile, topLevelConstructId);

        if (importInfo && importInfo.isLocal) {
            // Resolve the import path relative to the stack file
            const stackDir = path.dirname(stackFilePath);
            const resolvedImportPath = await this.resolveImportPath(stackDir, importInfo.path);

            if (resolvedImportPath && await this.fileExists(resolvedImportPath)) {
                try {
                    const importedFileContent = await fs.readFile(resolvedImportPath, 'utf-8');

                    // Search for the target construct within the imported file
                    const importedConstructResult = this.findConstructInImportedFile(
                        importedFileContent,
                        targetConstructId
                    );

                    if (importedConstructResult) {
                        return {
                            code: importedConstructResult.code,
                            lineNumber: importedConstructResult.lineNumber,
                            filePath: resolvedImportPath,
                            fileContent: importedFileContent,
                            isImported: true
                        };
                    } else {
                        return {
                            code: topLevelResult.code,
                            lineNumber: topLevelResult.lineNumber,
                            filePath: resolvedImportPath,
                            fileContent: importedFileContent,
                            isImported: true
                        };
                    }
                } catch (error) {
                    return null;
                }
            } else {
                return null;
            }
        } else {
            // The construct is defined inline in the stack
            return {
                code: topLevelResult.code,
                lineNumber: topLevelResult.lineNumber,
                filePath: stackFilePath,
                fileContent: stackContent,
                isImported: false
            };
        }
    }

    private findMatchingConstruct(sourceFile: ts.SourceFile, constructId: string): { code: string; lineNumber: number } | null {
        const visit = (node: ts.Node): ts.Node | null => {
            if (ts.isNewExpression(node) && node.arguments && node.arguments.length >= 2) {
                const firstArg = node.arguments[0];
                const secondArg = node.arguments[1];

                if (firstArg.kind === ts.SyntaxKind.ThisKeyword && ts.isStringLiteral(secondArg)) { //ts.isStringLiteral probably isn't robust enough
                    if (secondArg.text === constructId) {
                        return node;
                    }
                }
            }

            let result: ts.Node | null = null;

            ts.forEachChild(node, (child) => {
                if (!result)  result = visit(child);
            });

            return result;
        };

        const matchingNode = visit(sourceFile);

        if (matchingNode) {
            // Find the parent statement or declaration containing the construct
            const parentStatement = this.findParentStatement(matchingNode);
            const nodeToUse = parentStatement || matchingNode;

            const lineAndChar = sourceFile.getLineAndCharacterOfPosition(nodeToUse.getStart());
            return {
                code: nodeToUse.getText(sourceFile),
                lineNumber: lineAndChar.line + 1 // +1 because TypeScript lines are 0-based
            };
        }

        return null;
    }

    private findParentStatement(node: ts.Node): ts.Node | null {
        let current: ts.Node | undefined = node;

        while (current && current.parent) {
            // Check if current is a complete statement or declaration
            if (
                ts.isVariableStatement(current) || // const x = ...
                ts.isExpressionStatement(current) || // standalone expression with semicolon
                ts.isReturnStatement(current) || // return statement
                ts.isIfStatement(current) || // if statement
                ts.isForStatement(current) || // for loop
                ts.isForOfStatement(current) || // for...of loop
                ts.isForInStatement(current) || // for...in loop
                ts.isWhileStatement(current) || // while loop
                ts.isDoStatement(current) // do...while loop
            ) {
                return current;
            }

            // For variable declarations (which might be part of a VariableStatement)
            if (ts.isVariableDeclaration(current) && ts.isVariableDeclarationList(current.parent)) {
                // Continue up to get the complete variable statement
                current = current.parent;
                continue;
            }

            current = current.parent;
        }

        return null;
    }

    private findConstructImport(sourceFile: ts.SourceFile, constructName: string): { path: string; constructName: string; isLocal: boolean } | null {
        for (const statement of sourceFile.statements) {
            if (ts.isImportDeclaration(statement)) {
                const importClause = statement.importClause;
                if (!importClause || !importClause.namedBindings) continue;

                // Check if this is a named import (e.g., import { RedshiftConstruct } from '...')
                if (ts.isNamedImports(importClause.namedBindings)) {
                    const namedImports = importClause.namedBindings;

                    // Check if our construct is in the named imports
                    for (const element of namedImports.elements) {
                        if (element.name.text === constructName) {
                            // Found the construct in imports, get the import path
                            const moduleSpecifier = statement.moduleSpecifier;
                            if (ts.isStringLiteral(moduleSpecifier)) {
                                const importPath = moduleSpecifier.text;
                                const isLocal = importPath.startsWith('./') || importPath.startsWith('../');

                                return {
                                    path: importPath,
                                    constructName: constructName,
                                    isLocal: isLocal
                                };
                            }
                        }
                    }
                }
            }
        }

        return null;
    }

    private findConstructInImportedFile(fileContent: string, targetConstructId: string): ConstructInfo | null {
        const sourceFile = ts.createSourceFile(
            'imported-construct.ts',
            fileContent,
            ts.ScriptTarget.Latest,
            true
        );

        const result = this.findMatchingConstruct(sourceFile, targetConstructId);
        if (result) {
            return {
                code: result.code,
                lineNumber: result.lineNumber,
                filePath: '', // Will be set by caller
                fileContent: fileContent,
                isImported: true
            };
        }

        return null;
    }

    private async resolveImportPath(baseDir: string, importPath: string): Promise<string | null> {
        try {
            // Handle relative imports like './constructs/redshift-construct'
            if (importPath.startsWith('./') || importPath.startsWith('../')) {
                let resolvedPath = path.resolve(baseDir, importPath);

                // Try common TypeScript file extensions
                const extensions = ['.ts', '.js', '.tsx', '.jsx'];

                // First try the path as-is (in case it already has an extension)
                if (await this.fileExists(resolvedPath)) {
                    return resolvedPath;
                }

                // Try adding extensions
                for (const ext of extensions) {
                    const pathWithExt = resolvedPath + ext;
                    if (await this.fileExists(pathWithExt)) {
                        return pathWithExt;
                    }
                }

                // Try index files in directory
                for (const ext of extensions) {
                    const indexPath = path.join(resolvedPath, 'index' + ext);
                    if (await this.fileExists(indexPath)) {
                        return indexPath;
                    }
                }

                return null;
            }

            // For non-relative imports (npm packages), we don't resolve them
            return null;
        } catch (error) {
            return null;
        }
    }

    private async fileExists(filePath: string): Promise<boolean> {
        try {
            await fs.access(filePath);
            return true;
        } catch {
            return false;
        }
    }
}
