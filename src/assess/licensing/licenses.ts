export class Licenses {
    private static readonly LICENSES = [
        { name: 'AWS', value: 'AWS', default: true },
        { name: 'MIT', value: 'MIT' },
        { name: 'Apache', value: 'Apache' },
    ];

    static getAll(): { name: string, value: string }[] {
        return this.LICENSES;
    }

    static getDefault(): { name: string, value: string } {
        return this.LICENSES.filter(license => license.default)[0] || this.LICENSES[0];
    }

    static getByValue(value: string): { name: string, value: string } {
        const result = this.LICENSES.find(license => value.includes(license.value));

        if (!result) throw new Error(`License with value "${value}" not found`);

        return result;
    }
}