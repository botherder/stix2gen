import sys
import fileinput

from stix2.v21 import Bundle

from .ioc import IOC

def cli():
    objects = []

    for line in fileinput.input():
        ioc = IOC(line)
        ioc.clean()
        ioc.detect()

        if not ioc.ioc_type:
            continue

        stix2_obj = ioc.stix2()
        objects.append(stix2_obj)

    bundle = Bundle(objects=objects)
    sys.stdout.write(bundle.serialize(pretty=True))
