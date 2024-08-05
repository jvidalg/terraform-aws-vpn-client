# AWS vpn client endpoint with SAML authentication
resource "aws_ec2_client_vpn_endpoint" "vpn-client" {
  description            = "${var.project-name}-${var.environment}-vpn-client"
  server_certificate_arn = aws_acm_certificate.server.arn
  vpc_id                 = var.vpc_id
  security_group_ids     = [aws_security_group.vpn.id]
  client_cidr_block      = var.client_cidr_block
  session_timeout_hours  = var.session_timeout_hours

  split_tunnel = var.split_tunnel
  authentication_options {
    type = "federated-authentication"
    saml_provider_arn = aws_iam_saml_provider.google_workspace_saml_provider.arn
    self_service_saml_provider_arn = aws_iam_saml_provider.google_workspace_saml_provider.arn
  }
  connection_log_options {
    enabled               = true
    cloudwatch_log_group  = aws_cloudwatch_log_group.vpn-logs.name
    cloudwatch_log_stream = aws_cloudwatch_log_stream.vpn-logs-stream.name
  }
  tags = {
    Name        = "${var.project-name}-${var.environment}-vpn-client"
    Terraform   = "true"
    Environment = "${var.environment}"
  }
}

# Example SAML provider resource
resource "aws_iam_saml_provider" "google_workspace_saml_provider" {
  name                   = "GoogleWorkspaceSAMLProvider"
  saml_metadata_document = file("path/to/google_workspace_saml_metadata.xml")
}

# Example IAM role for SAML authentication
resource "aws_iam_role" "saml_role" {
  name               = "GoogleWorkspaceSAMLRole"
  assume_role_policy = data.aws_iam_policy_document.saml_assume_role_policy.json
}

# Example IAM policy for the role
resource "aws_iam_policy" "saml_policy" {
  name        = "GoogleWorkspaceSAMLVPNPolicy"
  description = "Policy for SAML VPN access"
  policy      = data.aws_iam_policy_document.saml_policy.json
}

data "aws_iam_policy_document" "saml_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithSAML"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_saml_provider.google_workspace_saml_provider.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = ["https://signin.aws.amazon.com/saml"]
    }
  }
}

data "aws_iam_policy_document" "saml_policy" {
  statement {
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
}
