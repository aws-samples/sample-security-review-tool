# DDB-002: DynamoDB data plane events must be captured by CloudTrail.
#
# Scenario: no-trail-captures-dynamodb-data-events
# This DynamoDB table exists in a template with no CloudTrail trail capturing
# DynamoDB data events, so the rule should fire.

resource "aws_dynamodb_table" "uncovered" {
  name         = "ddb-002-uncovered-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
