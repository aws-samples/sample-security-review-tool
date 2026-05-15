export function toPascalCase(value: string): string {
    return value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
}

export function toClassName(ruleId: string): string {
    return ruleId.split('-').map(toPascalCase).join('');
}

export function toInstanceName(ruleId: string): string {
    const parts = ruleId.toLowerCase().split('-');
    return parts[0] + parts.slice(1).map(p => p.charAt(0).toUpperCase() + p.slice(1)).join('');
}
