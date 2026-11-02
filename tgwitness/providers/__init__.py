import importlib

NAMES = ("hetzner", "digitalocean", "linode", "vultr", "aws", "phala", "generic")


def get(name):
    if name not in NAMES:
        raise ValueError("Unknown provider: " + str(name))
    return importlib.import_module("." + name, __name__).PROVIDER
