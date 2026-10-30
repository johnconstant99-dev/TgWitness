# Optional Compose configurations

[Project](../../README.md) · [Deployment guide](../../docs/DEPLOYMENT.md) · [Server Wiki](https://github.com/phishdestroy/TgWitness/wiki/Server-and-Docker)

Run these commands from the **project root**. The main `compose.yaml` stays there
for ordinary startup. For the prebuilt image, use `--project-directory .` with
`-f deploy/compose/compose.image.yaml`; this keeps `.env`, overlay paths and the
existing named volumes rooted in the project directory.

| Configuration | Purpose |
| --- | --- |
| [`compose.image.yaml`](compose.image.yaml) | Run a published image instead of building the source |
| [`compose.https.yaml`](compose.https.yaml) | Add Caddy and automatic HTTPS |
| [`compose.proxies.yaml`](compose.proxies.yaml) | Mount an operator-managed proxy catalog |
| [`compose.witness.yaml`](compose.witness.yaml) | Run an independent witness on its own server |

For HTTPS, configure `.env` as described in the deployment guide, then run:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
```

For an independent witness, configure its collector address and read-only token first:

```sh
docker compose --project-directory . -f deploy/compose/compose.witness.yaml up -d --build
```

`--project-directory .` keeps the standalone witness's build context and `.env`
relative to the project root. The collector's session and vault are never mounted
into the witness. See the [witness guide](../../docs/WITNESS.md).
