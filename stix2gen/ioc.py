# stix2gen
# Copyright (c) 2021-2022 Claudio Guarnieri
# Please check the file 'LICENSE' for copying permission.

import validators
from stix2.v21 import Indicator

IOC_TYPE_SHA256 = "sha256"
IOC_TYPE_DOMAIN = "domain"
IOC_TYPE_EMAIL = "email"
IOC_TYPE_IPV4 = "ipv4"
IOC_TYPE_IPV6 = "ipv6"
IOC_TYPE_APP_ID = "app_id"

IOC_MODELS = [
    {
        "type": IOC_TYPE_SHA256,
        "validator": validators.sha256,
        "stix2_pattern": "[file:hashes.sha256='{value}']"
    },
    {
        "type": IOC_TYPE_DOMAIN,
        "validator": validators.domain,
        "stix2_pattern": "[domain-name:value='{value}']",
    },
    {
        "type": IOC_TYPE_EMAIL,
        "validator": validators.email,
        "stix2_pattern": "[email-addr:value='{value}']",
    },
    {
        "type": IOC_TYPE_IPV4,
        "validator": validators.ipv4,
        "stix2_pattern": "[ipv4-addr:value='{value}']",
    },
    {
        "type": IOC_TYPE_IPV6,
        "validator": validators.ipv6,
        "stix2_pattern": "[ipv6-addr:value='{value}']",
    },
    {
        "type": IOC_TYPE_APP_ID,
        "validator": None,
        "stix2_pattern": "[app:id='{value}']",
    }
]


class IOC(object):

    def __init__(self, ioc, ioc_type=None):
        self.ioc = ioc
        self.ioc_type = ioc_type
        self.stix2_pattern = None
        if self.ioc_type:
            for ioc_model in IOC_MODELS:
                if ioc_model["type"] != self.ioc_type:
                    continue

                self.stix2_pattern = ioc_model.get("stix2_pattern")
                break

    def clean(self):
        self.ioc = self.ioc.strip().replace("[.]", ".").replace("[@]", "@")

    def detect(self):
        for ioc_model in IOC_MODELS:
            if not ioc_model.get("validator"):
                continue

            if ioc_model["validator"](self.ioc):
                self.ioc_type = ioc_model.get("type")
                self.stix2_pattern = ioc_model.get("stix2_pattern")
                return

    def stix2(self):
        if not self.ioc_type:
            return None

        return Indicator(indicator_types=["malicious-activity"],
                         pattern_type="stix",
                         pattern=self.stix2_pattern.format(value=self.ioc))
