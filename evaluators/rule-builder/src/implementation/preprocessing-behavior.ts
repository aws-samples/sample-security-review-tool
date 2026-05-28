export const PREPROCESSING_BEHAVIOR = `Before a rule evaluates a resource, the template passes through \`parseCfnTemplate\`. This function resolves intrinsic functions and pseudo-parameters in place. Understanding what values the rule will actually see is essential for writing correct fixtures.

## Pseudo-Parameters

These are replaced globally before any rule runs:

| Pseudo-Parameter | Resolved Value |
|-----------------|----------------|
| \`AWS::Region\` | \`"us-east-1"\` |
| \`AWS::AccountId\` | \`"123456789012"\` |
| \`AWS::Partition\` | \`"aws"\` |
| \`AWS::URLSuffix\` | \`"amazonaws.com"\` |
| \`AWS::StackName\` | \`"test-stack"\` |
| \`AWS::StackId\` | \`"arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/00000000-0000-0000-0000-000000000000"\` |
| \`AWS::NotificationARNs\` | \`[]\` |
| \`AWS::NoValue\` | \`undefined\` |

## Ref

\`{ Ref: "X" }\` resolves based on what "X" refers to:

- **Pseudo-parameter** → the value from the table above
- **Template Parameter** → the parameter's \`Default\` value, or the string \`"DEFAULT"\` if no default exists
- **Logical Resource ID** → the string \`"X"\` (the logical ID itself, NOT an ARN)
- **Anything else** → the string \`"DEFAULT"\`

### Examples

\`\`\`yaml
# Before preprocessing
BucketArn: !Ref MyBucket

# After preprocessing (MyBucket is a resource in the template)
BucketArn: "MyBucket"
\`\`\`

\`\`\`yaml
# Before preprocessing
Region: !Ref AWS::Region

# After preprocessing
Region: "us-east-1"
\`\`\`

\`\`\`yaml
# Before preprocessing (Environment is a Parameter with Default: "prod")
Env: !Ref Environment

# After preprocessing
Env: "prod"
\`\`\`

## Fn::GetAtt

\`{ "Fn::GetAtt": ["ResourceId", "AttributeName"] }\` resolves to just the logical resource ID string. The attribute name is discarded.

### Examples

\`\`\`yaml
# Before preprocessing
TrailArn: !GetAtt MyTrail.Arn

# After preprocessing
TrailArn: "MyTrail"
\`\`\`

\`\`\`yaml
# Before preprocessing
BucketDomainName: !GetAtt MyBucket.DomainName

# After preprocessing
BucketDomainName: "MyBucket"
\`\`\`

This means: if a rule checks whether a property value matches a resource in the template, it should compare against the logical ID string, not an ARN.

## Fn::Sub

\`{ "Fn::Sub": "string with \${references}" }\` substitutes pseudo-parameters and parameter defaults into the string. Resource references become the logical ID. Any remaining \${\`...\`} patterns are stripped (the \${ and } characters are removed).

### Examples

\`\`\`yaml
# Before preprocessing
BucketArn: !Sub "arn:aws:s3:::\${MyBucket}"

# After preprocessing (remaining \${} stripped)
BucketArn: "arn:aws:s3:::MyBucket"
\`\`\`

\`\`\`yaml
# Before preprocessing
LogGroup: !Sub "/aws/lambda/\${AWS::StackName}-function"

# After preprocessing
LogGroup: "/aws/lambda/test-stack-function"
\`\`\`

## Fn::FindInMap

\`{ "Fn::FindInMap": ["MapName", "Key", "SubKey"] }\` looks up the value in the template's \`Mappings\` section. The keys are resolved first (so they can be Refs or other intrinsics).

### Example

\`\`\`yaml
Mappings:
  RegionConfig:
    us-east-1:
      AMI: ami-12345

Resources:
  Instance:
    Properties:
      # Before preprocessing
      ImageId: !FindInMap [RegionConfig, !Ref "AWS::Region", AMI]

      # After preprocessing
      ImageId: "ami-12345"
\`\`\`

## What Remains Unresolved

These intrinsic functions are NOT resolved by preprocessing. They remain as opaque objects in the template:

- \`Fn::If\` — conditional logic stays as \`{ "Fn::If": ["ConditionName", valueIfTrue, valueIfFalse] }\`
- \`Fn::ImportValue\` — cross-stack references stay as \`{ "Fn::ImportValue": "..." }\`

Rules that encounter these must handle them as objects, not as resolved values. A common pattern is to treat unresolved intrinsics as "unknown" and not flag them (since the actual value depends on runtime conditions).

### Example

\`\`\`yaml
# Before preprocessing
Encrypted:
  Fn::If:
    - UseEncryption
    - true
    - false

# After preprocessing (UNCHANGED — still an object)
Encrypted:
  Fn::If:
    - UseEncryption
    - true
    - false
\`\`\`

## Template Parameters

Parameters with a \`Default\` value resolve to that default. Parameters without a default resolve to the string \`"DEFAULT"\`.

\`\`\`yaml
Parameters:
  BucketName:
    Type: String
    Default: "my-app-bucket"
  Environment:
    Type: String
    # No default

Resources:
  Bucket:
    Properties:
      # Before preprocessing
      BucketName: !Ref BucketName
      Tags:
        - Key: Env
          Value: !Ref Environment

      # After preprocessing
      BucketName: "my-app-bucket"
      Tags:
        - Key: Env
          Value: "DEFAULT"
\`\`\`

## Summary for Fixture Authors

When writing a fixture template:

1. If you want the rule to see a specific resource reference, use \`!Ref ResourceId\` or \`!GetAtt ResourceId.Attr\` — both will resolve to the string \`"ResourceId"\` after preprocessing.
2. If you want the rule to see a literal string value, just use the string directly — don't wrap it in an intrinsic.
3. If you want to test how the rule handles unresolvable values, use \`Fn::If\` or \`Fn::ImportValue\` — these stay as objects.
4. Pseudo-parameters always resolve to their fixed values. Don't use them expecting runtime variation.`;
