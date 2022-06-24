# stix2gen
# Copyright (c) 2021-2022 Claudio Guarnieri
# Please check the file 'LICENSE' for copying permission.

import re

from validators.utils import validator

MD5_REGEX = ".[A-Fa-f0-9]{32}$"
SHA1_REGEX = ".[A-Fa-f0-9]{40}$"
SHA256_REGEX = ".[A-Fa-f0-9]{64}$"
SHA512_REGEX = ".[A-Fa-f0-9]{128}$"


@validator
def validator_md5(target):
    r = re.compile(MD5_REGEX)
    return r.match(target)


@validator
def validator_sha1(target):
    r = re.compile(SHA1_REGEX)
    return r.match(target)


@validator
def validator_sha256(target):
    r = re.compile(SHA256_REGEX)
    return r.match(target)


@validator
def validator_sha512(target):
    r = re.compile(SHA512_REGEX)
    return r.match(target)
