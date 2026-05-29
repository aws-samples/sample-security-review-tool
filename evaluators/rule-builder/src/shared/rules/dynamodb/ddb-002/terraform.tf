# DDB-002 fixture: trigger 'no-trail-captures-dynamodb-data-events'.
#
# The control fires when no aws_cloudtrail resource in the template captures
# DynamoDB data plane events for the assessed aws_dynamodb_table. To trigger
# the finding we declare a DynamoDB table with NO accompanying CloudTrail
# trail in the template, so hasTrailCapturingDynamoDbDataEvents() returns
# false and the finding is emitted.

resource "aws_dynamodb_table" "uncovered" {
  name         = "ddb-002-uncovered-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
