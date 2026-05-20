import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (Terraform): Lambda function's tracing configuration block is
 * conditionally included via an unresolvable condition (e.g., a dynamic
 * block driven by a value unknown at plan time).
 *
 * Expected: PASS — when it cannot be determined at analysis time whether the
 * tracing_config block is present/active, the rule must not flag the
 * resource to avoid false positives. The TF adapter treats plan values that
 * are surfaced as object placeholders containing the `__unknown__` sentinel
 * as unresolved.
 */
describe('LAMBDA-004 REQ-07 (TF): unresolvable conditional tracing configuration', () => {
  const factory = new Lambda004TfAdapterFactory();

  it('does not flag aws_lambda_function whose tracing_config block is unknown at plan time', () => {
    const resource = {
      address: 'aws_lambda_function.conditional_tracing',
      type: 'aws_lambda_function',
      name: 'conditional_tracing',
      values: {
        function_name: 'fn-with-conditional-tracing',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        // The whole block is unresolved — surfaced as an object placeholder
        // rather than the usual array of nested blocks.
        tracing_config: { __unknown__: true },
      },
    } as never;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does not flag aws_lambda_function whose tracing_config.mode is unknown at plan time', () => {
    const resource = {
      address: 'aws_lambda_function.conditional_mode',
      type: 'aws_lambda_function',
      name: 'conditional_mode',
      values: {
        function_name: 'fn-with-conditional-tracing-mode',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        tracing_config: [
          { mode: { __unknown__: true } },
        ],
      },
    } as never;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
