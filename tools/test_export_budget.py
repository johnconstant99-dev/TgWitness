"""A session budget accounts for preparation, unknown scope and recorded transfer progress."""
import asyncio
from pathlib import Path
import sys

import httpx
import pytest
from telethon import errors

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import export_budget as budget  # noqa: E402
from tgwitness.sealed import create_app  # noqa: E402
from tgwitness.sealed_crypto import keypair  # noqa: E402
from tgwitness.verify import verify_bundle  # noqa: E402
from tools.browser_fixtures import CapsuleClient, config  # noqa: E402
from tools.test_sealed_account import login, ExportTransport  # noqa: E402


def sample(messages=1000, media=0, chats=1):
    return {'performed': True, 'dialog_inventory_complete': True, 'visible_selected_chats': chats,
            'chats': [{'history_messages': messages, 'sample_messages': 25, 'request_seconds': .5,
                       'download_bytes': media, 'hash_ranges': 0, 'unknown_size_files': 0, 'text_bytes': 1000}]}


def test_budget_spends_only_the_remaining_session_and_reserves_packaging():
    result = budget.plan(sample(), {'transport': 'regular'}, 600, 7200)
    assert result['fit'] == 'estimated_fit' and result['messages_to_read'] == 1000
    assert result['sealing_reserve_seconds'] >= 300
    assert result['collection_seconds'] == 600 - result['sealing_reserve_seconds']
    assert result['estimated_total_seconds'] < 600
    late = budget.plan(sample(), {}, 290, 7200)
    assert late['fit'] == 'no_collection_time' and late['collection_seconds'] == 0


def test_large_files_do_not_fit_and_text_only_recalculation_changes_the_plan():
    heavy = budget.plan(sample(10000, 25 * 100 * budget.MIB), {'max_total_gib': 4}, 7200, 7200)
    assert heavy['fit'] in {'over_budget', 'no_collection_time'}
    assert heavy['files_exceed_budget'] and 'messages_only' in heavy['suggestions']
    text = budget.plan(sample(10000), {'media_action': 'exclude'}, 7200, 7200)
    assert text['fit'] == 'estimated_fit' and text['download_bytes'] == 0


@pytest.mark.parametrize('change,options', [
    ({'visible_selected_chats': 2}, {}), ({'dialog_inventory_complete': False}, {}),
    ({'selected_inventory_complete': False}, {}), ({}, {'include_stories': True}),
    ({}, {'transport': 'takeout', 'chat_ids': []}), ({}, {'from_utc': '2026-11-01T00:00:00+00:00'}),
])
def test_incomplete_measurements_cannot_claim_the_whole_selection_fits(change, options):
    measured = sample()
    measured.update(change)
    result = budget.plan(measured, options, 7200, 7200)
    assert result['fit'] == 'unknown' and result['unknown']


def test_unknown_totals_and_file_sizes_remain_explicit():
    measured = sample()
    measured['chats'][0]['history_messages'] = None
    assert 'history_count' in budget.plan(measured, {}, 7200, 7200)['unknown']
    measured['chats'][0].update(history_messages=1000, unknown_size_files=1)
    assert 'file_size' in budget.plan(measured, {}, 7200, 7200)['unknown']


def test_waits_and_actual_slow_transfers_revise_the_time_budget():
    estimate = budget.plan(sample(10000, 25 * budget.MIB), {}, 7200, 7200)
    job = {'counts': {'unique_media_bytes': 10 * budget.MIB},
           'acquisition': {'messages_preserved': 10000, 'bytes_preserved': 1024, 'history_complete': True}}
    slow = budget.progress(estimate, job, 600, 7200, 300)
    assert slow['fit'] == 'over_budget'
    assert slow['measured_download_bytes_per_second'] == 10 * budget.MIB / 300
    waiting = budget.progress(estimate, job, 600, 7200, 300, 86400)
    assert waiting['fit'] == 'wait_exceeds_window' and waiting['wait_seconds'] == 86400


def test_packaging_starts_before_the_session_deadline_and_preserves_a_verified_partial(tmp_path):
    async def run():
        cfg = config(keypair())
        app = create_app(tmp_path / 'data', tmp_path / 'out', cfg, CapsuleClient)

        class Waiting(ExportTransport):
            account_id = 44
            async def open(self):
                raise errors.TakeoutInitDelayError(None, capture=86400)

        async with app.router.lifespan_context(app):
            session = app.state.session
            session.account_export.transport_factory = Waiting
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test',
                                         headers={'Authorization': 'Bearer ' + cfg['token']}) as client:
                await login(client, session, '2fa')
                response = await client.post('/api/collect', json={'mode': 'account', 'account_options': {'transport': 'takeout'}})
                assert response.status_code == 200, response.text
                await session.account_export.task
                assert session.status()['time_budget']['fit'] == 'wait_exceeds_window'
                session.started -= 50
                assert session.status()['remaining_seconds'] > 0
                await asyncio.wait_for(asyncio.shield(session.monitor_task), 10)
                assert session.phase == 'sealed' and session.reason == 'packaging_reserve'
                verified = verify_bundle(tmp_path / 'out/evidence.zip')['account_export']
                assert not verified['complete_within_scope'] and verified['counts']['messages'] == 0
                assert 'packaging_reserve' in verified['coverage']['gaps'][0]
                assert session.revocation == 'revoked'
    asyncio.run(run())


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
