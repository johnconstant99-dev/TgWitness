import asyncio
from xml.etree import ElementTree as ET

import pytest

from tgwitness.network import NetworkConfig
from tgwitness.s3 import S3


@pytest.mark.parametrize("tokens", ([None], ["same", "same"], ["first", "second", "first"]))
def test_invalid_continuation_stops_instead_of_repeating_requests(tokens):
    calls = 0
    client = S3("https://storage.example", "region", "bucket", "access", "secret", NetworkConfig(kind="direct"))

    async def call(*_args):
        nonlocal calls
        calls += 1
        if calls > len(tokens):
            raise AssertionError("Invalid pagination caused another storage request")
        root = ET.Element("ListBucketResult")
        ET.SubElement(root, "IsTruncated").text = "true"
        if tokens[calls - 1] is not None:
            ET.SubElement(root, "NextContinuationToken").text = tokens[calls - 1]
        return 200, {}, ET.tostring(root)

    client.call = call

    async def read():
        return [item async for item in client.list("workspace/")]

    with pytest.raises(ValueError, match="continuation"):
        asyncio.run(read())
    assert calls == len(tokens)
