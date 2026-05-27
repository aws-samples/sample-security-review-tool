import * as cdk from 'aws-cdk-lib';
import { FixtureStack } from './fixture-stack';

const app = new cdk.App();
new FixtureStack(app, 'FixtureStack');
