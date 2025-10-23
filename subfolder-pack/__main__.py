from pulumi_policy import (
    PolicyPack,
)
from alb_policies import alb_logging_policies, alb_listener_http_policies, alb_target_group_deregistration_policies, alb_target_group_healthcheck_policies
from secrets_policies import secret_manager_secret_kms_policies

PolicyPack(
    name="python-demo-pack",
    policies=[
        alb_logging_policies,
        alb_listener_http_policies,
        alb_target_group_healthcheck_policies,
        alb_target_group_deregistration_policies,
        secret_manager_secret_kms_policies
    ],
)
