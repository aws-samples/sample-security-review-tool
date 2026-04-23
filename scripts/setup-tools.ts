import { ScannerSetup } from '../src/config/scanner/scanner-setup.js';

process.env.SRT_APP_DIR = process.cwd();

const setup = new ScannerSetup(console.log);
await setup.installMissingScanners();
