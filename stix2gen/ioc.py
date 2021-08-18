import validators
from stix2.v21 import Bundle, DomainName, Indicator, Malware, Relationship


IOC_TYPE_DOMAIN = "domain"
IOC_TYPE_EMAIL = "email"
IOC_TYPE_IPV4 = "ipv4"
IOC_TYPE_IPV6 = "ipv6"
IOC_VALIDATORS = [
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
    }
]

class IOC(object):

    def __init__(self, ioc, ioc_type=None):
        self.ioc = ioc
        self.ioc_type = ioc_type
        self.stix2_pattern = None

    def clean(self):
        self.ioc = self.ioc.strip().replace("[.]", ".").replace("[@]", "@")

    def detect(self):
        for validator in IOC_VALIDATORS:
            if validator["validator"](self.ioc):
                self.ioc_type = validator.get("type")
                self.stix2_pattern = validator.get("stix2_pattern")

    def stix2(self):
        if not self.ioc_type:
            return None

        return Indicator(indicator_types=["malicious-activity"],
                         pattern_type="stix",
                         pattern=self.stix2_pattern.format(value=self.ioc))
