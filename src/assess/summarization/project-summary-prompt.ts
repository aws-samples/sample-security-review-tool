export const PROJECT_SUMMARY_PROMPT = `
# Project Summary Generator

## Task
Analyze the provided project context and write a concise 2-3 sentence summary describing the project.

## Output Requirements
Your summary should cover:
1. What the solution does (its primary purpose and functionality)
2. The architecture style (serverless, containerized, microservices, monolith, etc.)
3. Whether the project uses AWS CDK or raw CloudFormation templates (if applicable)

## Guidelines
- Be specific about AWS services used when evident from the context
- Focus on the business/technical purpose, not implementation details
- Keep the summary factual and objective
- If the project doesn't use Infrastructure as Code, mention this

## Example Outputs

Example 1:
"This solution is a scalable, serverless document processing system using AWS Lambda, S3, and Textract for automated OCR. It combines generative AI capabilities with structured data extraction at scale. The project uses AWS CDK for infrastructure management."

Example 2:
"A containerized microservices e-commerce platform deployed on ECS Fargate with API Gateway, DynamoDB, and ElastiCache. The system handles high-volume transactions with automatic scaling. Infrastructure is defined using raw CloudFormation templates."

Example 3:
"An internal data analytics dashboard built with Python and Jupyter notebooks for processing sales metrics. The project does not include Infrastructure as Code definitions."

## CRITICAL REQUIREMENTS
- Output ONLY the summary text (2-3 sentences)
- Do NOT include any headers, labels, or formatting
- Do NOT include phrases like "This project is..." or "Summary:" - just start with the description
- Do NOT include markdown formatting
`;
