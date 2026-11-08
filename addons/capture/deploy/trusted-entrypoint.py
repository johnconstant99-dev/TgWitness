import ipaddress
import json
import os
import subprocess
from pathlib import Path

from tgwitness_capture.trusted_runtime import connector_config


def firewall(host, port):
    address = ipaddress.IPv4Address(host)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid proxy port")
    return f"""table inet trusted_live {{
 chain output {{
  type filter hook output priority 0; policy drop;
  oifname "lo" ip daddr 127.0.0.1 accept
  ct state established,related accept
  ip daddr {address} tcp dport {port} accept
 }}
}}
"""


def main():
    config = json.loads(Path("/config.json").read_text())
    options = config["trusted"]
    connectors = connector_config(options["connectors"])
    chosen = os.environ.get("TRUSTED_CONNECTOR", "")
    if chosen not in connectors:
        raise ValueError("Set TRUSTED_CONNECTOR to an explicitly selected configured connector")
    connector = connectors[chosen]
    subprocess.run(["nft", "-f", "-"], input=firewall(connector["host"], connector["port"]).encode(), check=True)
    receipt = {"policy": "trusted-live-deny-direct-v1", "host": connector["host"], "port": connector["port"],
               "netns": os.readlink("/proc/self/ns/net")}
    route_path = "/run/trusted-route.json"
    with os.fdopen(os.open(route_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as target:
        json.dump(receipt, target)
    os.chmod(route_path, 0o400)
    subprocess.run(["setfacl", "-m", "u:10001:r--", route_path], check=True)
    for directory in ("/data", "/session", "/exports", "/home/recorder"):
        os.chown(directory, 10001, 10001)
    os.execvp("setpriv", ["setpriv", "--reuid=10001", "--regid=10001", "--init-groups",
                           "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                           "python", "/app/trusted-display.py"])


if __name__ == "__main__":
    main()
