from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

from shared.models import SecurityEvent

USERS = [
    ("alice", "human"),
    ("bob", "human"),
    ("carol", "human"),
    ("svc-billing", "service_account"),
    ("svc-deploy", "service_account"),
    ("root-admin", "root"),
]
COUNTRIES = ["US", "CA", "GB", "DE", "IN", "JP"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]
SERVICES = {
    "iam": ["ConsoleLogin", "CreateUser", "AttachUserPolicy", "UpdateLoginProfile"],
    "s3": ["GetObject", "PutObject", "ListBuckets", "DeleteObject"],
    "ec2": ["DescribeInstances", "RunInstances", "TerminateInstances"],
    "kms": ["Decrypt", "Encrypt", "ScheduleKeyDeletion"],
}
USER_AGENTS = ["aws-cli/2.15", "terraform/1.8", "console-browser", "boto3/1.34"]


class EventSimulator:
    def __init__(self) -> None:
        self.user_home_country = {
            "alice": "US",
            "bob": "US",
            "carol": "GB",
            "svc-billing": "US",
            "svc-deploy": "US",
            "root-admin": "US",
        }

    def next_event(self) -> SecurityEvent:
        if random.random() < 0.18:
            return self._anomalous_event()
        return self._baseline_event()

    def _baseline_event(self) -> SecurityEvent:
        user_id, principal_type = random.choice(USERS)
        service_name = random.choice(list(SERVICES))
        api_action = random.choice(SERVICES[service_name])
        country = self.user_home_country[user_id]
        region = random.choice(REGIONS)
        auth_result = "success" if random.random() > 0.12 else "failure"

        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            cloud_provider="aws",
            account_id=f"acct-{random.randint(1001, 1003)}",
            user_id=user_id,
            principal_type=principal_type,
            source_ip=self._random_ip(),
            geo_country=country,
            region=region,
            service_name=service_name,
            api_action=api_action,
            resource_type=self._resource_type(service_name),
            resource_id=f"{service_name}-{random.randint(1000, 9999)}",
            auth_result=auth_result,
            bytes_sent=random.randint(0, 50_000),
            bytes_received=random.randint(100, 150_000),
            device_fingerprint=f"device-{random.randint(1, 15)}",
            user_agent=random.choice(USER_AGENTS),
            is_privileged_action=api_action in {"CreateUser", "AttachUserPolicy", "ScheduleKeyDeletion"},
            metadata={"scenario": "baseline"},
        )

    def _anomalous_event(self) -> SecurityEvent:
        scenario = random.choice(
            [
                "failed-login-burst",
                "privileged-new-country",
                "data-exfiltration-spike",
                "delete-burst",
            ]
        )
        user_id, principal_type = random.choice(USERS)

        if scenario == "failed-login-burst":
            service_name = "iam"
            api_action = "ConsoleLogin"
            auth_result = "failure"
            country = random.choice(COUNTRIES)
            region = random.choice(REGIONS)
            bytes_received = random.randint(0, 200)
            privileged = False
        elif scenario == "privileged-new-country":
            service_name = "iam"
            api_action = random.choice(["CreateUser", "AttachUserPolicy"])
            auth_result = "success"
            country = random.choice([c for c in COUNTRIES if c != self.user_home_country[user_id]])
            region = random.choice(REGIONS)
            bytes_received = random.randint(200, 2_000)
            privileged = True
        elif scenario == "data-exfiltration-spike":
            service_name = "s3"
            api_action = "GetObject"
            auth_result = "success"
            country = self.user_home_country[user_id]
            region = "us-east-1"
            bytes_received = random.randint(2_000_000, 8_000_000)
            privileged = False
        else:
            service_name = random.choice(["s3", "ec2", "kms"])
            api_action = random.choice(["DeleteObject", "TerminateInstances", "ScheduleKeyDeletion"])
            auth_result = "success"
            country = self.user_home_country[user_id]
            region = "us-west-2"
            bytes_received = random.randint(500, 20_000)
            privileged = True

        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            cloud_provider="aws",
            account_id=f"acct-{random.randint(1001, 1003)}",
            user_id=user_id,
            principal_type=principal_type,
            source_ip=self._random_ip(),
            geo_country=country,
            region=region,
            service_name=service_name,
            api_action=api_action,
            resource_type=self._resource_type(service_name),
            resource_id=f"{service_name}-{random.randint(1000, 9999)}",
            auth_result=auth_result,
            bytes_sent=random.randint(0, 25_000),
            bytes_received=bytes_received,
            device_fingerprint=f"device-{random.randint(20, 40)}",
            user_agent=random.choice(USER_AGENTS),
            is_privileged_action=privileged,
            metadata={"scenario": scenario},
        )

    @staticmethod
    def _random_ip() -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    @staticmethod
    def _resource_type(service_name: str) -> str:
        return {
            "iam": "user",
            "s3": "object",
            "ec2": "instance",
            "kms": "key",
        }[service_name]

