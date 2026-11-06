"""A stored recipient replica needs the recipient key and authenticated envelopes."""
import asyncio
import base64
import hashlib
import io
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.replica import (CHUNK, ReplicaSettings, decrypt, encrypt, require_evidence_lock, upload, workspace_prefix)
from tgwitness.s3 import S3


class Destination:
    async def put(self, name, body, length, sha, md5, extra):
        self.data = b''.join([chunk async for chunk in body])
        assert len(self.data) == length
        assert hashlib.sha256(self.data).hexdigest() == sha
        assert base64.b64encode(hashlib.md5(self.data).digest()).decode() == md5
        return {'etag': 'test-etag', 'version_id': 'test-version'}

    async def head(self, name, version):
        assert version == 'test-version'
        return {'etag': 'test-etag', 'version_id': version, 'last_modified': '2026-10-01T00:00:00+00:00'}


@pytest.mark.parametrize('length', [0, 17, CHUNK, CHUNK + 13, 2 * CHUNK])
def test_recipient_roundtrip_and_legacy(length):
    recipient = X25519PrivateKey.generate()
    public = base64.b64encode(recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    data, old_key, name = b'x' * length, b'k' * 32, 'synthetic/object.tgwr'
    target, receipts = Destination(), []
    asyncio.run(upload(target, old_key, name, lambda: io.BytesIO(data), {}, recipient_public_key=public, receipts=receipts))
    assert target.data.startswith(b'TGWR2')
    with pytest.raises(ValueError, match='нужен ключ получателя'):
        b''.join(decrypt(old_key, name, io.BytesIO(target.data).read))
    assert b''.join(decrypt(old_key, name, io.BytesIO(target.data).read, recipient)) == data
    for alternate_name, key in [(name + 'changed', recipient), (name, X25519PrivateKey.generate())]:
        with pytest.raises(InvalidTag):
            b''.join(decrypt(old_key, alternate_name, io.BytesIO(target.data).read, key))
    tampered = bytearray(target.data)
    tampered[50] ^= 1
    with pytest.raises(InvalidTag):
        b''.join(decrypt(old_key, name, io.BytesIO(tampered).read, recipient))
    legacy = b''.join(encrypt(old_key, name, io.BytesIO(data).read, b'n' * 8))
    assert legacy.startswith(b'TGWR1')
    assert b''.join(decrypt(old_key, name, io.BytesIO(legacy).read)) == data
    assert receipts[0]['last_modified'] and receipts[0]['version_id'] == 'test-version'
    assert 'not an independently signed timestamp' in receipts[0]['time_verification']


@pytest.mark.parametrize('enabled,mode,days', [(False, 'COMPLIANCE', 1), (None, 'COMPLIANCE', 1),
                                             (True, 'GOVERNANCE', 1), (True, 'COMPLIANCE', 0)])
def test_each_evidence_lock_requirement_is_mandatory(enabled, mode, days):
    s3 = AsyncMock()
    s3.object_lock.return_value = {'enabled': enabled}
    settings = ReplicaSettings(evidence=True, retention_mode=mode, retention_days=days).model_dump()
    with pytest.raises(ValueError, match='Object Lock.*Compliance'):
        asyncio.run(require_evidence_lock(s3, settings))
    settings.update(retention_mode='COMPLIANCE', retention_days=1)
    s3.object_lock.return_value = {'enabled': True}
    asyncio.run(require_evidence_lock(s3, settings))


@pytest.mark.parametrize('value', ['a', base64.b64encode(b'x' * 31).decode(), base64.b64encode(bytes(32)).decode()])
def test_invalid_public_keys_are_refused(value):
    with pytest.raises(ValueError):
        ReplicaSettings(recipient_public_key=value)


def test_s3_receipt_uses_specific_version_and_never_substitutes_response_date():
    s3 = S3('https://s3.invalid', 'us-east-1', 'synthetic', 'synthetic', 'synthetic', None)
    s3.call = AsyncMock(return_value=(200, {'ETag': 'e', 'x-amz-version-id': 'v/1',
                                           'Date': 'Thu, 01 Oct 2026 00:00:00 GMT'}, b''))
    result = asyncio.run(s3.put('name', b'', 0, '00' * 32, 'md5'))
    assert result['last_modified'] is None
    s3.call.return_value = (200, {'ETag': 'e', 'x-amz-version-id': 'v/1',
                                  'Last-Modified': 'Thu, 01 Oct 2026 00:00:00 GMT'}, b'')
    assert asyncio.run(s3.head('name', 'v/1'))['last_modified'] == '2026-10-01T00:00:00+00:00'
    assert s3.call.call_args.args[1].endswith('?versionId=v%2F1')


def test_recipient_switch_has_separate_namespace():
    settings = ReplicaSettings().model_dump()
    signer = base64.b64encode(b's' * 32).decode()
    previous = workspace_prefix(settings, signer)
    settings['recipient_public_key'] = base64.b64encode(b'r' * 32).decode()
    assert workspace_prefix(settings, signer).startswith(previous + '/recipient-')


def test_panel_refuses_evidence_mode_before_saving():
    from tools.check_session_reservations import workspace
    async def run():
        async with workspace() as (app, client):
            app.state.store.set_setting('route_policy', {'outside_enabled': True, 'exposure': 'fallback'})
            body = dict(enabled=True, endpoint='https://s3.invalid', bucket='synthetic',
                        access_key='synthetic', secret_key='synthetic', evidence=True, retention_days=1)
            s3 = AsyncMock()
            s3.object_lock.return_value = {'enabled': True}
            with patch('tgwitness.replica.client', return_value=s3):
                response = await client.post('/api/replica', json=body)
                assert response.status_code == 422, response.text
                assert 'Compliance' in response.text
                assert not app.state.store.get_setting('replica', {}).get('enabled')
    asyncio.run(run())
