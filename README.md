# stix2gen

stix2gen is a simple utility to generate [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro.html) indicators file from a list of provided indicators.

## Install

You can install stix2gen with the following command:

```bash
$ pip3 install stix2gen
```

## Usage

Generate a STIX2 by automatically detecting the indicators types:

```bash
$ cat domains.txt emails.txt | stix2gen --malware-name NewMalware
```

You can also optionally provide a description using `--malware-desc`.

Pipe the output to save to a file:

```bash
$ cat domains.txt emails.txt | stix2gen --malware-name NewMalware > newmalware.stix2
```

**Please note**: certain types of indicators might be misclassified when run through stix2gen's automatic detection. This is for example the case with app IDs (such as Android package names), which will be otherwise automatically detected as a domain name. In order to process app IDs you should explicitly specify a separate file including those indicators:

```bash
$ cat domains.txt emails.txt | stix2gen --malware-name NewMalware --app-ids-file package_names.txt > newmalware.stix2
```
