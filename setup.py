import os

from setuptools import find_packages, setup

__package_name__ = "stix2gen"
__version__ = "1.0"
__description__ = "STIX2 file generator"

this_directory = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(this_directory, "README.md")
with open(readme_path, encoding="utf-8") as handle:
    long_description = handle.read()

requires = (
    "stix2>=3.0.0",
    "validators>=0.18.2",
)

setup(
    name=__package_name__,
    version=__version__,
    author="Claudio Guarnieri",
    author_email="nex@nex.sx",
    description=__description__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/botherder/stix2gen",
    entry_points={
        "console_scripts": [
            "stix2gen = stix2gen:cli",
        ],
    },
    install_requires=requires,
    packages=find_packages(),
    include_package_data=True,
    keywords="security malware",
    license="MIT",
    classifiers=[
    ],
)
