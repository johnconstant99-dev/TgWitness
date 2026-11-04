import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from pydantic import ValidationError

from tgwitness import report, report_profiles
from tgwitness.store import Store
from tools.check_prepared_export_access import grant_session
from tools.check_session_reservations import workspace


@pytest.mark.parametrize("field", sorted(report_profiles.CASE_FIELDS))
def test_case_material_cannot_enter_reusable_profiles(field):
    with pytest.raises(ValidationError, match="layout settings only"):
        report_profiles.Profile(name="Reusable", options={field: {} if field == "selection" else "Sensitive"})


def test_replace_persist_limit_and_remove_do_not_change_report(tmp_path):
    store = Store(tmp_path)
    try:
        original = report.ReportOptions(case_title="Current case", review_findings="Current findings",
                                        selection={"enabled": True, "chats": [-123]})
        report.save(store, original)
        saved = report_profiles.save(store, report_profiles.Profile(name="Brief", options={"timeline": False}))
        changed = report_profiles.save(store, report_profiles.Profile(name="BRIEF", options={"design": "atlas"}))
        assert saved["id"] == changed["id"] and len(report_profiles.catalog(store)) == 1
        assert changed["options"]["design"] == "atlas"
        assert not (set(changed["options"]) & report_profiles.CASE_FIELDS)
        assert report.saved(store) == original
        for index in range(49):
            report_profiles.save(store, report_profiles.Profile(name=f"Layout {index}", options={}))
        with pytest.raises(ValueError, match="50"):
            report_profiles.save(store, report_profiles.Profile(name="Overflow", options={}))
        report_profiles.remove(store, changed["id"])
        assert report.saved(store) == original
        assert len(report_profiles.catalog(store)) == 49
        with pytest.raises(ValueError, match="no longer exists"):
            report_profiles.remove(store, changed["id"])
    finally:
        store.close()
    reopened = Store(tmp_path)
    try:
        assert len(report_profiles.catalog(reopened)) == 49
    finally:
        reopened.close()


@pytest.mark.parametrize("options", [{"unknown": True}, {"language": "bogus"}, {"chart_limit": 500}])
def test_invalid_layout_is_rejected(options):
    with pytest.raises(ValidationError):
        report_profiles.Profile(name="Invalid", options=options)


def test_api_permissions_scope_and_workspace_isolation():
    async def run():
        async with workspace() as (app, client):
            _, reader = grant_session(app, permissions=["view"])
            payload = {"name": "Layout", "options": {"timeline": False, "language": "ru"}}
            response = await client.post('/api/report-profiles', json=payload)
            assert response.status_code == 200, response.text
            saved = response.json()
            assert (await client.get('/api/report-profiles', headers=reader)).status_code == 200
            assert (await client.post('/api/report-profiles', headers=reader, json=payload)).status_code == 403
            assert (await client.delete('/api/report-profiles/'+saved['id'], headers=reader)).status_code == 403
            assert (await client.post('/api/report-profiles', json={**payload, 'options': {'selection': {}}})).status_code == 422
            assert not report.saved(app.state.store).case_title
            created = await client.post('/api/profiles', json={'label': 'Other investigation'})
            assert created.status_code == 200, created.text
            other = created.json()['id']
            isolated = await client.get('/profiles/'+other+'/api/report-profiles')
            assert isolated.status_code == 200 and not isolated.json()['profiles']
            assert (await client.delete('/profiles/'+other+'/api/report-profiles/'+saved['id'])).status_code == 404
            assert len((await client.get('/api/report-profiles')).json()['profiles']) == 1
            assert (await client.delete('/api/report-profiles/'+saved['id'])).status_code == 200
    asyncio.run(run())


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
