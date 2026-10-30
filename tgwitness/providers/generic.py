"""Any server installed by hand with install.sh: no provider API, so never more than self-attested.

Nobody independent saw how this server was set up: whoever ran the installer had root before it,
and the provider's own records are not available to a verifier. The installer records what the
host looked like before installation, installs one commit and closes SSH; all of it self-reported.
"""
import json
import socket

from .base import Provider


class Generic(Provider):
    key, title, name = "generic", "Any server (self-attested)", "generic"
    limits = ("Self-attested: everything about this host comes from the host itself. Whoever ran the installer "
              "had root before it ran, and no provider record is available to the verifier.",)

    @classmethod
    def credentials(cls, path):
        return ""

    def __init__(self, credentials="", session=None, log=None):
        self.log = [] if log is None else log

    @staticmethod
    def metadata(request, root):
        installed = json.loads((root / "etc/tgwitness/install.json").read_text())
        return {"instance_id": (root / "etc/machine-id").read_text().strip(), "hostname": socket.gethostname(),
                "public_ipv4": None, "region": None, "user_data_sha256": installed["sha256"],
                "user_data_redacted_sha256": installed["redacted_sha256"],
                "preinstall_sha256": installed.get("preinstall_sha256")}


PROVIDER = Generic
