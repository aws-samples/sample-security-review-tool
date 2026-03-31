import * as ts from 'typescript';
import * as fs from 'fs';
import * as path from 'path';

export interface CdkStackInfo {
	className: string;
	filePath: string;
	sourceCode: string;
}

export class CdkStackFinder {
	public findStackClass(entryPointPath: string, stackId: string): CdkStackInfo | null {
		const entryPointContent = fs.readFileSync(entryPointPath, 'utf8');
		const sourceFile = ts.createSourceFile(
			entryPointPath,
			entryPointContent,
			ts.ScriptTarget.Latest,
			true
		);

		const stackInstantiations = this.findAllStackInstantiations(sourceFile);

		let className: string | null = null;

		if (stackInstantiations.length === 1) {
			className = stackInstantiations[0];
		} else if (stackInstantiations.length > 1) {
			className = this.findStackClassName(sourceFile, stackId);

			if (!className) {
				return null;
			}
		} else {
			return null;
		}

		const importPath = this.findImportPath(sourceFile, className);
		if (!importPath) {
			return null;
		}

		const resolvedPath = this.resolveFilePath(path.dirname(entryPointPath), importPath);
		if (!resolvedPath) {
			return null;
		}

		return {
			className: className,
			filePath: resolvedPath,
			sourceCode: fs.readFileSync(resolvedPath, 'utf8')
		};
	}

	private findAllStackInstantiations(sourceFile: ts.SourceFile): string[] {
		const stackClasses: string[] = [];

		const visit = (node: ts.Node) => {
			if (ts.isNewExpression(node) && node.arguments && node.arguments.length >= 2) {
				const firstArg = node.arguments[0];

				// Check if first argument is a cdk.App (or variable that holds one)
				if (this.isAppArgument(firstArg) && ts.isIdentifier(node.expression)) {
					stackClasses.push(node.expression.text);
				}
			}

			ts.forEachChild(node, visit);
		};

		visit(sourceFile);

		return stackClasses;
	}

	private isAppArgument(arg: ts.Expression): boolean {
		if (ts.isNewExpression(arg)) {
			if (ts.isPropertyAccessExpression(arg.expression)) {
				return arg.expression.expression &&
					ts.isIdentifier(arg.expression.expression) &&
					arg.expression.expression.text === 'cdk' &&
					arg.expression.name.text === 'App';
			}
			if (ts.isIdentifier(arg.expression)) {
				return arg.expression.text === 'App';
			}
		}

		if (ts.isIdentifier(arg)) {
			return true; // For now, assume any identifier could be an app
		}

		return false;
	}

	private findStackClassName(sourceFile: ts.SourceFile, stackId: string): string | null {
		let className: string | null = null;

		const visit = (node: ts.Node) => {
			if (ts.isNewExpression(node) && node.arguments && node.arguments.length >= 2) {
				const secondArg = node.arguments[1];

				let hasStackId = false;

				if (ts.isStringLiteral(secondArg) && secondArg.text === stackId) {
					hasStackId = true;
				} else if (ts.isTemplateExpression(secondArg)) {
					hasStackId = this.matchesTemplatePattern(secondArg, stackId);
				}

				if (hasStackId && ts.isIdentifier(node.expression)) {
					className = node.expression.text;
					return;
				}
			}

			ts.forEachChild(node, visit);
		};

		visit(sourceFile);
		return className;
	}

	private matchesTemplatePattern(templateExpr: ts.TemplateExpression, stackId: string): boolean {
		let pattern = this.escapeRegex(templateExpr.head.text);

		for (const span of templateExpr.templateSpans) {
			pattern += '(.+?)';
			pattern += this.escapeRegex(span.literal.text);
		}

		const regex = new RegExp(`^${pattern}$`);

		return regex.test(stackId);
	}

	private escapeRegex(text: string): string {
		return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	}

	private findImportPath(sourceFile: ts.SourceFile, className: string): string | null {
		let importPath: string | null = null;

		const visit = (node: ts.Node) => {
			if (ts.isImportDeclaration(node) && node.importClause && node.moduleSpecifier) {
				const moduleSpecifier = node.moduleSpecifier;
				if (ts.isStringLiteral(moduleSpecifier)) {
					const namedBindings = node.importClause.namedBindings;
					if (namedBindings && ts.isNamedImports(namedBindings)) {
						for (const element of namedBindings.elements) {
							if (element.name.text === className) {
								importPath = moduleSpecifier.text;
								break;
							}
						}
					}
				}
			}
			ts.forEachChild(node, visit);
		};

		visit(sourceFile);
		return importPath;
	}

	private resolveFilePath(baseDir: string, importPath: string): string | null {
		const extensions = ['.ts', '.tsx', '.js', '.jsx'];
		const basePath = path.resolve(baseDir, importPath);

		for (const ext of extensions) {
			const fullPath = basePath + ext;
			if (fs.existsSync(fullPath)) {
				return fullPath;
			}
		}

		for (const ext of extensions) {
			const indexPath = path.join(basePath, 'index' + ext);
			if (fs.existsSync(indexPath)) {
				return indexPath;
			}
		}

		return null;
	}
}
