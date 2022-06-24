# stix2gen
# Copyright (c) 2021-2022 Claudio Guarnieri
# Please check the file 'LICENSE' for copying permission.

import sys

import click
from stix2.v21 import Bundle, Malware, Relationship

from .ioc import IOC, IOC_TYPE_APP_ID


@click.group()
def cli():
    pass


@cli.command()
@click.option("--malware-name", help="Malware name", required=True)
@click.option("--malware-desc", help="Malware descrition")
@click.option("--app-ids-file", help="App IDs File", type=click.File("r"))
@click.option("--source-file", help="File", type=click.File("r"),
              default=sys.stdin)
def cli(malware_name, malware_desc, app_ids_file, source_file):
    objects = []

    malware = Malware(name=malware_name, description=malware_desc,
                      is_family=True)

    for line in source_file.readlines():
        ioc = IOC(line)
        ioc.clean()

        if not ioc.ioc:
            continue

        ioc.detect()

        if not ioc.ioc_type:
            continue

        stix2_obj = ioc.stix2()
        objects.append(stix2_obj)
        objects.append(Relationship(stix2_obj, "indicates", malware))

    if app_ids_file:
        for line in app_ids_file.readlines():
            ioc = IOC(ioc=line, ioc_type=IOC_TYPE_APP_ID)
            ioc.clean()

            stix2_obj = ioc.stix2()
            objects.append(stix2_obj)
            objects.append(Relationship(stix2_obj, "indicates", malware))

    bundle = Bundle(objects=objects)
    sys.stdout.write(bundle.serialize(pretty=True))
