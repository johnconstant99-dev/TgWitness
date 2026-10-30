"""Server providers for high-assurance deployments (python -m tgwitness.cloud).

A provider module creates the server through its own API behind a provider firewall without
inbound rules, lets a verifier read back that server, its firewall and the provider's own log
of actions, and tells the collector on the server how to read the provider's metadata service.
"generic" is the exception: any server installed by hand, never more than self-attested.
"""
import importlib

NAMES = ("hetzner", "digitalocean", "linode", "vultr", "aws", "generic")


def get(name):
    if name not in NAMES:
        raise ValueError("Unknown provider: " + str(name))
    return importlib.import_module("." + name, __name__).PROVIDER
