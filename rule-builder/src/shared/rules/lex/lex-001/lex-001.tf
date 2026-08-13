# LEX-001 fixture
#
# Scenario CHILD_DIRECTED_NOT_TRUE is triggered below for both applicable
# resource types (aws_lex_bot and aws_lexv2models_bot) by explicitly setting
# the COPPA child-directed declaration to false.
#
# Scenario MISSING_DATA_PRIVACY cannot be expressed in Terraform: both
# aws_lex_bot's `child_directed` argument and aws_lexv2models_bot's
# `data_privacy` block (and its nested `child_directed` attribute) are
# Required in the Terraform AWS provider schema, mirroring the underlying
# Lex API requirement. Any configuration that omits them fails
# `terraform validate` before the plan is ever produced, so there is no way
# to author a resource that reaches the "no data privacy configuration"
# branch of the control while still producing a valid plan.

resource "aws_lex_bot" "child_directed_not_true" {
  name              = "OrderFlowersBot"
  child_directed    = false
  process_behavior  = "SAVE"

  abort_statement {
    message {
      content      = "Sorry, I could not understand. Goodbye."
      content_type = "PlainText"
    }
  }

  intent {
    intent_name    = "OrderFlowers"
    intent_version = "$LATEST"
  }
}

resource "aws_lexv2models_bot" "child_directed_not_true" {
  name                        = "example-v2-bot"
  idle_session_ttl_in_seconds = 300
  role_arn                    = "arn:aws:iam::123456789012:role/service-role/AmazonLexV2BotRole"

  data_privacy {
    child_directed = false
  }
}
