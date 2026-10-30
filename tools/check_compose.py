"""Exercise real Docker Compose in a unique, disposable project with no accounts."""
import http.client
import json
import os
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    project = "tgwitness-check-" + uuid.uuid4().hex[:12]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("TGWITNESS_", "COMPOSE_"))}
    environment["TGWITNESS_PORT"] = "0"  # Let Docker reserve an unused loopback port.
    command = ["docker", "compose", "--project-name", project,
               "-f", str(ROOT / "compose.yaml")]

    def compose(*arguments, capture=False):
        return subprocess.run([*command, *arguments], cwd=ROOT, env=environment,
                              check=True, text=True, capture_output=capture, timeout=600)

    def request(path, token=None):
        address = compose("port", "tgwitness", "8787", capture=True).stdout.strip()
        host, port = address.rsplit(":", 1)
        assert host == "127.0.0.1", address
        connection = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            headers = {"Authorization": "Bearer " + token} if token else {}
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    try:
        compose("up", "-d", "--build", "--wait", "--wait-timeout", "180")
        assert request("/")[0] == 200
        assert request("/api/status")[0] == 401
        token = compose("exec", "-T", "tgwitness", "cat", "/data/panel-token.txt", capture=True).stdout.strip()
        code, body = request("/api/status", token)
        assert code == 200
        original = json.loads(body)
        assert not original["demo"]
        compose("down")  # Remove the container, keep this test project's volume.
        compose("up", "-d", "--wait", "--wait-timeout", "180")
        code, body = request("/api/status", token)
        assert code == 200, "Panel token did not survive container replacement"
        reopened = json.loads(body)
        assert reopened["fingerprint"] == original["fingerprint"], "Signing identity changed"
        assert reopened["stats"]["total"] >= original["stats"]["total"]
        print(json.dumps({"passed": True, "loopback_only": True, "api_requires_token": True,
                          "token_and_signing_identity_survive_recreation": True}))
    finally:
        # The UUID project is created above, so these are only this check's resources.
        compose("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
