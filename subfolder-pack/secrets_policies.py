from pulumi_policy import (
    EnforcementLevel,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy
)

__all__ = ["secret_manager_secret_kms_policies"]

def secret_manager_secret_customer_key_required(args: ResourceValidationArgs, report_violation: ReportViolation):
    if args.resource_type == "aws:secretsmanager/secret:Secret":
        kms_key_id = args.props.get("kmsKeyId")
        if not kms_key_id:
            report_violation(
                "AWS Secrets Manager secrets must use a customer-managed KMS key.",
                args.props.get("urn")
            )

secret_manager_secret_kms_policies = ResourceValidationPolicy(
    name="secret-manager-secret-kms-key",
    description="Ensure Secrets Manager secrets use customer-managed KMS keys",
    enforcement_level=EnforcementLevel.ADVISORY,
    validate=[
        secret_manager_secret_customer_key_required
    ],
)