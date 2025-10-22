from pulumi_policy import (
    EnforcementLevel,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy
)

__all__ = ["alb_logging_policies",
           "alb_listener_http_policies", "alb_target_group_healthcheck_policies", "alb_target_group_deregistration_policies"]


def enable_access_logging_validator(args: ResourceValidationArgs, report_violation: ReportViolation):
    if args.resource_type in [
        # add the rest of the lb types (from the different modules)
        "aws:lb/loadBalancer:LoadBalancer",
    ]:
        access_logs = args.props.get("accessLogs", {})
        if not access_logs.get("enabled"):
            report_violation(
                "ALB LoadBalancers should have access logging enabled and configured.", args.props.get("urn"))


def disallow_unencrypted_traffic(args: ResourceValidationArgs, report_violation: ReportViolation):
    if args.resource_type in [
        # add rest of the listener types (in different modules)
        "aws:lb/loadBalancer:LoadBalancer"
    ]:
        port = args.props.get("port")
        protocol = args.props.get("protocol")

        if port == 80 and protocol == "HTTP":
            has_valid_redirect = False
            default_actions = args.props.get("defaultActions", [])

            for action in default_actions:
                if action.get("type") == "redirect":
                    redirect_config = action.get("redirect", {})
                    if (redirect_config.get("port") == "443" and
                        redirect_config.get("protocol") == "HTTPS" and
                            redirect_config.get("statusCode") == "HTTP_301"):
                        has_valid_redirect = True
                        break

            if not has_valid_redirect:
                report_violation(
                    "ALB Listener on port 80 with HTTP protocol must have a redirect default action "
                    "to port 443, protocol HTTPS with status code HTTP_301.",
                    args.props.get("urn")
                )


def target_group_healthcheck_settings(args: ResourceValidationArgs, report_violation: ReportViolation):
    if args.resource_type in [
        "aws:lb/loadBalancer:LoadBalancer"
    ]:
        health_check = args.props.get("healthCheck", {})
        if health_check.get("enabled"):
            if int(health_check.get("interval")) > 10:
                report_violation(
                    "The interval between health checks for a target group should not be greater than 10 seconds", args.props["urn"])
        else:
            report_violation(
                "Target group health checks should be enabled", args.props.get("urn"))


def target_group_deregistration_settings(args: ResourceValidationArgs, report_violation: ReportViolation):
    if args.resource_type in [
        "aws:alb/targetGroup:TargetGroup"
    ]:
        if args.props.get("deregistrationDelay") == None or int(args.props["deregistrationDelay"]) > 5:
            report_violation(
                "Target group deregistration settings should not be longer than 5 seconds", args.props.get("urn"))


alb_logging_policies = ResourceValidationPolicy(
    name="aws-alb-accesslogs-configuration",
    description="Ensures ALB LoadBalancers have access logging enabled.",
    enforcement_level=EnforcementLevel.ADVISORY,
    validate=[
        enable_access_logging_validator
    ],
)

alb_listener_http_policies = ResourceValidationPolicy(
    name="aws-alb-listener-http-redirect",
    description="Ensures ALB Listeners on port 80/HTTP have proper HTTPS redirect configured",
    enforcement_level=EnforcementLevel.ADVISORY,
    validate=[
        disallow_unencrypted_traffic
    ],
)

alb_target_group_healthcheck_policies = ResourceValidationPolicy(
    name="aws-alb-target-group-healthcheck",
    description="Ensures ALB Target Groups have useful healthchecks",
    enforcement_level=EnforcementLevel.ADVISORY,
    validate=[
        target_group_healthcheck_settings,
    ],
)

alb_target_group_deregistration_policies = ResourceValidationPolicy(
    name="aws-alb-target-group-deregistration",
    description="Ensures ALB Target Groups have useful deregistration settings",
    enforcement_level=EnforcementLevel.ADVISORY,
    validate=[
        target_group_deregistration_settings
    ]
)
