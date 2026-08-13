## LEX-002: Amazon Lex V2 bot slots must have obfuscation enabled for slot values
##
## Scenario: obfuscation-disabled
## Triggered by aws_lexv2models_slot.unobfuscated, whose obfuscation_setting
## explicitly sets obfuscation_setting_type = "None", leaving slot values
## unmasked in conversation logs.

resource "aws_iam_role" "lex_bot_role" {
  name = "lex-v2-bot-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lexv2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_lexv2models_bot" "example" {
  name     = "order-support-bot"
  role_arn = aws_iam_role.lex_bot_role.arn

  data_privacy {
    child_directed = false
  }

  idle_session_ttl_in_seconds = 300
}

resource "aws_lexv2models_bot_locale" "example" {
  bot_id                          = aws_lexv2models_bot.example.id
  bot_version                     = "DRAFT"
  locale_id                       = "en_US"
  n_lu_intent_confidence_threshold = 0.4
}

resource "aws_lexv2models_intent" "order_intent" {
  name        = "OrderStatus"
  bot_id      = aws_lexv2models_bot.example.id
  bot_version = aws_lexv2models_bot_locale.example.bot_version
  locale_id   = aws_lexv2models_bot_locale.example.locale_id
}

resource "aws_lexv2models_slot" "unobfuscated" {
  name        = "AccountNumber"
  bot_id      = aws_lexv2models_bot.example.id
  bot_version = aws_lexv2models_bot_locale.example.bot_version
  locale_id   = aws_lexv2models_bot_locale.example.locale_id
  intent_id   = aws_lexv2models_intent.order_intent.intent_id

  slot_type_id = "AMAZON.Number"

  value_elicitation_setting {
    slot_constraint = "Required"

    prompt_specification {
      max_retries = 2

      message_group {
        message {
          plain_text_message {
            value = "What is your account number?"
          }
        }
      }
    }
  }

  # Explicitly disables slot value obfuscation, so account numbers appear
  # in plain text in conversation logs -- this is what LEX-002 detects.
  obfuscation_setting {
    obfuscation_setting_type = "None"
  }
}
