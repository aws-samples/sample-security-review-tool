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

## Fn::Join

\`{ "Fn::Join": [delimiter, [part1, part2, ...]] }\` is collapsed into a single string when — and only when — every part resolves to a scalar. Each part is resolved recursively first (so \`Ref\` to a pseudo-parameter/parameter, \`Fn::Sub\`, \`Fn::FindInMap\`, and nested \`Fn::Join\` parts are substituted using the same rules above), then the resolved parts are concatenated with the delimiter.

If ANY part stays an object after resolution, the whole \`Fn::Join\` is left intact as an opaque object — it is NOT partially collapsed. The common culprits are parts that preprocessing does not resolve to a scalar: \`Fn::ImportValue\`, \`Fn::If\`, \`Fn::Select\`, \`Fn::Split\`, \`Fn::GetAZs\`, and \`Fn::GetAtt\`. Note \`Fn::GetAtt\` is especially treacherous: it "resolves" to the referenced resource's logical ID string (see the Fn::GetAtt section above), so a join containing one technically collapses — but to a string built from a meaningless logical ID, not the real attribute value. Treat a \`Fn::GetAtt\`-derived join as unusable, not as a real value.

### Examples

\`\`\`yaml
# Before preprocessing
ImageUri:
  Fn::Join:
    - ""
    - - !Ref AWS::AccountId
      - .dkr.ecr.
      - !Ref AWS::Region
      - .amazonaws.com/my-repo:latest

# After preprocessing
ImageUri: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest"
\`\`\`

\`\`\`yaml
# Before preprocessing (one part is an unresolvable import)
Endpoint:
  Fn::Join:
    - ""
    - - !ImportValue SharedHost
      - "/path"

# After preprocessing (UNCHANGED — still an object)
Endpoint:
  Fn::Join:
    - ""
    - - Fn::ImportValue: SharedHost
      - "/path"
\`\`\`

This distinction is what determines whether a rule can see a value at all. CDK rarely emits a literal string for a property built from other inputs — it synthesizes an \`Fn::Join\`. Whether that join collapses depends ENTIRELY on what the parts are:

- Built from account id, region, partition, URL suffix, or template parameters (\`Ref\` to a pseudo-parameter/parameter) → every part resolves → the join COLLAPSES to a usable string the rule can inspect.
- Built from a CREATED resource's runtime attribute — e.g. \`repository.repositoryUri\`, \`bucket.bucketArn\`, \`table.tableArn\`, or any \`resource.someAttr\` token — synthesizes to a join over \`Fn::GetAtt\`/\`Fn::Select\`/\`Fn::Split\` → does NOT resolve to a usable scalar → the join stays an opaque object and the rule sees "unknown".

So an adapter must NOT assume the property is only ever a literal a human typed — it must handle both the collapsed-string case and the opaque-object case (treating the latter as unknown and not flagging).

## What Remains Unresolved

These intrinsic functions are NOT resolved by preprocessing. They remain as opaque objects in the template:

- \`Fn::If\` — conditional logic stays as \`{ "Fn::If": ["ConditionName", valueIfTrue, valueIfFalse] }\`
- \`Fn::ImportValue\` — cross-stack references stay as \`{ "Fn::ImportValue": "..." }\`
- \`Fn::Select\`, \`Fn::Split\`, \`Fn::GetAZs\`, \`Fn::Base64\`, \`Fn::Cidr\` — preprocessing has no filter for these; they stay as objects
- \`Fn::Join\` — left intact when ANY part stays an object after resolution (see above); otherwise it is collapsed to a string

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
4. Pseudo-parameters always resolve to their fixed values. Don't use them expecting runtime variation.
5. A value built from \`Fn::Join\` over resolvable parts collapses to the concatenated string. When authoring a CDK fixture you usually do not control this directly — constructs that derive a value from account id, region, or another resource's attribute synthesize to \`Fn::Join\`, which the rule will see as the collapsed literal. Verify the rule and its adapter read that collapsed string, not just a hand-typed literal.`;
