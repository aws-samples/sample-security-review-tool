export const DIAGRAM_GENERATOR_PROMPT = `
# Diagram Generator Instructions

## Task
Analyze the provided CloudFormation template and create a data flow diagram using Mermaid markdown syntax. Focus on the primary data flows that involve customer data, external integrations, or cross-service boundaries. Internal service communications may be simplified for clarity.

## Data Flow Diagram Definition
A data-flow diagram is a way of representing a flow of data through a process or a system (usually an information system). The DFD shows **what** data flows between components, not **how** or **when** the flows occur. The DFD also provides information about the outputs and inputs of each entity and the process itself. A data-flow diagram has no control flow — there are no decision rules and no loops. Specific operations based on the data can be represented by a flowchart.

For each data flow, at least one of the endpoints (source and/or destination) must exist in a process. The refined representation of a process can be done in another data-flow diagram, which subdivides this process into sub-processes.

## Example 1: Simple Web Application
\`\`\`mermaid
flowchart TD
    User[Customer]
    CloudFront((CloudFront CDN))
    ALB((Application Load Balancer))
    ECS((ECS Service))
    RDS[(RDS Database)]
    S3[(S3 Bucket)]

    User -->|HTTPS Request| CloudFront
    CloudFront -->|Request| ALB
    ALB -->|Request| ECS
    ECS -->|SQL Query| RDS
    ECS -->|File Upload| S3
    RDS -->|Query Result| ECS
    S3 -->|File Access| ECS
    ECS -->|Response| ALB
    ALB -->|Response| CloudFront
    CloudFront -->|HTTPS Response| User
\`\`\`

## Example 2: API Gateway with Lambda
\`\`\`mermaid
flowchart TD
    Client[External Client]
    APIGateway((API Gateway))
    Lambda((Lambda Function))
    DynamoDB[(DynamoDB Table)]
    S3[(S3 Bucket)]
    SQS[(SQS Queue)]

    Client -->|API Request| APIGateway
    APIGateway -->|Event| Lambda
    Lambda -->|Read/Write| DynamoDB
    Lambda -->|Store Object| S3
    Lambda -->|Send Message| SQS
    DynamoDB -->|Data| Lambda
    S3 -->|Object| Lambda
    Lambda -->|Response| APIGateway
    APIGateway -->|JSON Response| Client
\`\`\`

## Diagram Conventions:
- Use AWS service names (CloudFront, Lambda, RDS, etc.)
- Label data flows with data type (API Request, SQL Query, File Upload)
- Use standard AWS architectural symbols: ((Service)), [(Storage)], [External Entity]
- Include security-relevant flows (authentication, encryption boundaries)
- Show separate arrows for request/response flows to clearly indicate data direction
- Bidirectional arrows (↔) should only be used for true bidirectional data exchange

## CRITICAL REQUIREMENTS
- **The diagram MUST be wrapped in triple backtick mermaid code blocks (\`\`\`\` \`\`\`mermaid ... \`\`\` \`\`\`\`) when calling the tool. Failure to include these markers will result in the diagram not rendering properly.**
- **Return ONLY the Mermaid diagram wrapped in triple backtick code blocks**
- **Do not include any explanatory text, analysis, or descriptions**
- **Do not include titles, headers, or additional commentary**
`;
