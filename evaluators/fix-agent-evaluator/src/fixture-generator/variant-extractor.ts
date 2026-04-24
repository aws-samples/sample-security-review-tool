import type { FindingVariant } from './types.js';

/**
 * Statically extracts finding variants from a security-matrix rule's TypeScript
 * source. Each createResult / createScanResult call that passes a distinct fix
 * string becomes one variant. Returns an empty array when the rule has zero or
 * one unique fix text (no multi-variant testing needed).
 */
export function extractVariants(ruleBody: string): FindingVariant[] {
    const fixTexts = extractFixTexts(ruleBody);
    const unique = deduplicatePreservingOrder(fixTexts);
    if (unique.length <= 1) return [];
    return unique.map((text, i) => ({
        variantId: `v${i + 1}`,
        fixGuidance: text,
        label: text.slice(0, 60).replace(/\n/g, ' '),
    }));
}

function extractFixTexts(source: string): string[] {
    const texts: string[] = [];
    const callPattern = /this\.create(?:Scan)?Result\s*\(/g;
    let match: RegExpExecArray | null;

    while ((match = callPattern.exec(source)) !== null) {
        const argsStart = match.index + match[0].length;
        const argsText = extractBalancedArgs(source, argsStart - 1);
        if (!argsText) continue;

        const fixArg = extractLastStringArg(argsText);
        if (fixArg !== null) {
            texts.push(fixArg);
            continue;
        }

        const methodFix = resolveHelperMethod(source, argsText);
        if (methodFix !== null) {
            texts.push(methodFix);
        }
    }
    return texts;
}

/**
 * Starting at the open paren, returns the text between the outermost parens.
 * Handles nested parens, strings, and template literals.
 */
function extractBalancedArgs(source: string, openParen: number): string | null {
    let depth = 0;
    let i = openParen;
    while (i < source.length) {
        const ch = source[i];
        if (ch === '(') {
            depth++;
        } else if (ch === ')') {
            depth--;
            if (depth === 0) return source.slice(openParen + 1, i);
        } else if (ch === "'" || ch === '"' || ch === '`') {
            i = skipString(source, i);
        } else if (ch === '/' && i + 1 < source.length && source[i + 1] === '/') {
            while (i < source.length && source[i] !== '\n') i++;
        }
        i++;
    }
    return null;
}

function skipString(source: string, start: number): number {
    const quote = source[start];
    let i = start + 1;
    while (i < source.length) {
        if (source[i] === '\\') { i += 2; continue; }
        if (source[i] === quote) return i;
        i++;
    }
    return i;
}

/**
 * Splits the args text by top-level commas, then returns the string value
 * of the last argument if it's a string literal. Returns null if the last
 * arg is not a recognizable string.
 */
function extractLastStringArg(argsText: string): string | null {
    const args = splitTopLevelCommas(argsText);
    if (args.length === 0) return null;
    const lastArg = args[args.length - 1].trim();
    return parseStringLiteral(lastArg);
}

function splitTopLevelCommas(text: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let start = 0;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if (ch === ')' || ch === ']' || ch === '}') depth--;
        else if (ch === "'" || ch === '"' || ch === '`') {
            i = skipString(text, i);
        } else if (ch === ',' && depth === 0) {
            parts.push(text.slice(start, i));
            start = i + 1;
        }
    }
    parts.push(text.slice(start));
    return parts;
}

function parseStringLiteral(text: string): string | null {
    const trimmed = text.trim();
    if (trimmed.length < 2) return null;
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === "'" || first === '"' || first === '`') && first === last) {
        return trimmed.slice(1, -1).replace(/\\n/g, '\n').replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    return null;
}

/**
 * When the last arg is a method call like `this.buildAddConfigFix()`, try
 * to find that method's body and extract its return string.
 */
function resolveHelperMethod(source: string, argsText: string): string | null {
    const args = splitTopLevelCommas(argsText);
    if (args.length === 0) return null;
    const lastArg = args[args.length - 1].trim();

    const methodCall = lastArg.match(/^this\.(\w+)\s*\(\s*\)$/);
    if (!methodCall) return null;

    const methodName = methodCall[1];
    const methodPattern = new RegExp(
        `(?:private|protected|public)?\\s+${methodName}\\s*\\([^)]*\\)\\s*(?::\\s*\\w+)?\\s*\\{`,
    );
    const methodMatch = methodPattern.exec(source);
    if (!methodMatch) return null;

    const bodyStart = methodMatch.index + methodMatch[0].length;
    const bodyText = extractBalancedBraces(source, bodyStart - 1);
    if (!bodyText) return null;

    const returnMatch = bodyText.match(/return\s+(['"`])/);
    if (!returnMatch) return null;

    const strStart = bodyText.indexOf(returnMatch[0]) + 'return '.length;
    return parseStringLiteral(bodyText.slice(strStart).trim().replace(/;\s*$/, ''));
}

function extractBalancedBraces(source: string, openBrace: number): string | null {
    let depth = 0;
    let i = openBrace;
    while (i < source.length) {
        const ch = source[i];
        if (ch === '{') depth++;
        else if (ch === '}') {
            depth--;
            if (depth === 0) return source.slice(openBrace + 1, i);
        } else if (ch === "'" || ch === '"' || ch === '`') {
            i = skipString(source, i);
        }
        i++;
    }
    return null;
}

function deduplicatePreservingOrder(texts: string[]): string[] {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const text of texts) {
        if (!seen.has(text)) {
            seen.add(text);
            result.push(text);
        }
    }
    return result;
}
