from . import access as routes_access
from . import accounts as routes_accounts
from . import chats as routes_chats
from . import cloud as routes_cloud
from . import documentation as routes_documentation
from . import evidence as routes_evidence
from . import export as routes_export
from . import network as routes_network
from . import secret_chats as routes_secret_chats
from . import system as routes_system
from .topology import topology
from .system_map import system_map
from . import witness as routes_witness
from .. import cloud_wizard
from .. import extensions
from ..board_api import register as register_board
from ..capture_api import register as register_capture
from ..channel_graph import register as register_channel_graph
from ..webapp import register as register_webapp
from ..conversation_api import register as register_conversation
from ..translation_api import register as register_translation
from ..search_record import register as register_search_record
from ..subject import register as register_subject
from ..undercover import register as register_undercover
from ..presence_watch import register as register_presence
from ..qr_codes import register as register_qr
from ..watchlists import register as register_watchlists
from ..middleware import RequestLimit
from ..panel_assets import PanelFiles
from ..panel_routes import register as register_panel
from ..profiles import ProfileDispatch
from ..request_security import RequestSecurity
from ..search_api import register as register_search
from ..settings_hub import register as register_settings
from ..storage_api import register as register_storage
from ..webhook_api import register as register_webhooks
from fastapi import APIRouter
from fastapi import Depends
from fastapi.exceptions import RequestValidationError
from pathlib import Path
import os


def register(app, ctx):
    authenticate = ctx.authenticate
    router = APIRouter()
    ctx.installation_id = os.environ.get("TGWITNESS_INSTALLATION_ID", "")
    router.get("/_tgwitness/ready", include_in_schema=False)(
        routes_system.installation_ready
    )
    app.state.operation_lock, app.state.closing = (ctx.op_lock, False)
    app.include_router(router)
    router = APIRouter()
    app.add_middleware(RequestLimit, max_body=16384)
    app.middleware("http")(ctx.headers)
    app.exception_handler(Exception)(ctx.unexpected_error)
    app.exception_handler(RequestValidationError)(ctx.validation_error)
    router.get("/locale.js")(routes_system.locale)
    router.get("/api/demo-access")(routes_system.demo_access)
    router.get("/api/status", dependencies=[Depends(authenticate)])(
        routes_system.status
    )
    router.get("/api/topology", dependencies=[Depends(authenticate)])(topology)
    router.get("/api/system-map", dependencies=[Depends(authenticate)])(system_map)
    app.include_router(router)
    router = APIRouter()
    if ctx.allow_profiles:
        router.get("/api/profiles", dependencies=[Depends(authenticate)])(
            routes_accounts.profiles_list
        )
        ctx.cloud_jobs = app.state.cloud_jobs = cloud_wizard.Jobs(ctx.root)
        router.get("/api/cloud", dependencies=[Depends(authenticate)])(
            routes_cloud.cloud_status
        )
        router.post("/api/cloud/check", dependencies=[Depends(authenticate)])(
            routes_cloud.cloud_check
        )
        router.post("/api/cloud/deploy", dependencies=[Depends(authenticate)])(
            routes_cloud.cloud_deploy
        )
        router.post("/api/cloud/destroy", dependencies=[Depends(authenticate)])(
            routes_cloud.cloud_destroy
        )
        router.post("/api/cloud/address", dependencies=[Depends(authenticate)])(
            routes_cloud.cloud_address
        )
        router.get(
            "/api/cloud/deployments/{name}/{filename}",
            dependencies=[Depends(authenticate)],
        )(routes_cloud.cloud_file)
        router.post("/api/profiles", dependencies=[Depends(authenticate)])(
            routes_accounts.profiles_create
        )
        router.get("/api/profile-groups", dependencies=[Depends(authenticate)])(
            routes_accounts.profile_groups
        )
        router.post("/api/profile-groups", dependencies=[Depends(authenticate)])(
            routes_accounts.profile_group_create
        )
        router.patch(
            "/api/profile-groups/{group_id}", dependencies=[Depends(authenticate)]
        )(routes_accounts.profile_group_update)
        router.delete(
            "/api/profile-groups/{group_id}", dependencies=[Depends(authenticate)]
        )(routes_accounts.profile_group_delete)
        router.post(
            "/api/profile-groups/{group_id}/apply", dependencies=[Depends(authenticate)]
        )(routes_accounts.profile_group_apply)
        router.put(
            "/api/profiles/{profile_id}/group", dependencies=[Depends(authenticate)]
        )(routes_accounts.profile_group_assign)
        from ..group_settings import register as register_group_settings

        app.include_router(router)
        router = APIRouter()
        register_group_settings(app, authenticate, ctx.require_live)
        from ..group_overview import register as register_group_overview

        register_group_overview(app, authenticate)
        from ..group_export import register as register_group_export

        register_group_export(app, authenticate)
        router.post("/api/profiles/import", dependencies=[Depends(authenticate)])(
            routes_accounts.profiles_import
        )
        router.post("/api/profiles/check", dependencies=[Depends(authenticate)])(
            routes_accounts.profiles_check
        )
        router.post("/api/multi-export/start", dependencies=[Depends(authenticate)])(
            routes_accounts.multi_export_start
        )
        router.post("/api/multi-export/plan", dependencies=[Depends(authenticate)])(
            routes_accounts.multi_export_plan
        )
        router.get("/api/multi-export/current", dependencies=[Depends(authenticate)])(
            routes_accounts.multi_export_current
        )
        router.get("/api/multi-export/jobs", dependencies=[Depends(authenticate)])(
            routes_accounts.multi_export_jobs
        )
        router.get(
            "/api/multi-export/{export_id}", dependencies=[Depends(authenticate)]
        )(routes_accounts.multi_export_poll)
        router.post(
            "/api/multi-export/{export_id}/pause", dependencies=[Depends(authenticate)]
        )(routes_accounts.multi_export_pause)
        router.post(
            "/api/multi-export/{export_id}/resume", dependencies=[Depends(authenticate)]
        )(routes_accounts.multi_export_resume)
        router.post(
            "/api/multi-export/{export_id}/cancel", dependencies=[Depends(authenticate)]
        )(routes_accounts.multi_export_cancel)
        router.get(
            "/api/multi-export/{export_id}/download",
            dependencies=[Depends(authenticate)],
        )(routes_accounts.multi_export_download)
        router.patch(
            "/api/profiles/{profile_id}", dependencies=[Depends(authenticate)]
        )(routes_accounts.profiles_rename)
        router.delete(
            "/api/profiles/{profile_id}", dependencies=[Depends(authenticate)]
        )(routes_accounts.profiles_delete)
        app.include_router(router)
        router = APIRouter()
    router.get("/api/events", dependencies=[Depends(authenticate)])(
        routes_system.get_events
    )
    router.get("/api/stream", dependencies=[Depends(authenticate)])(
        routes_system.journal_stream
    )
    router.post("/api/auth/configure", dependencies=[Depends(authenticate)])(
        routes_accounts.configure
    )
    router.post("/api/auth/phone/start", dependencies=[Depends(authenticate)])(
        routes_accounts.start_phone
    )
    router.post("/api/auth/session/new", dependencies=[Depends(authenticate)])(
        routes_accounts.independent_session
    )
    router.post("/api/auth/import", dependencies=[Depends(authenticate)])(
        routes_accounts.import_account
    )
    router.post("/api/auth/import/preview", dependencies=[Depends(authenticate)])(
        routes_accounts.import_preview
    )
    router.post("/api/auth/qr/start", dependencies=[Depends(authenticate)])(
        routes_accounts.start_qr
    )
    router.get("/api/auth/qr/{login_id}", dependencies=[Depends(authenticate)])(
        routes_accounts.poll_qr
    )
    router.post("/api/auth/qr/{login_id}/cancel", dependencies=[Depends(authenticate)])(
        routes_accounts.cancel_qr
    )
    router.post("/api/network", dependencies=[Depends(authenticate)])(
        routes_network.network
    )
    router.get("/api/connection", dependencies=[Depends(authenticate)])(
        routes_network.connection_state
    )
    router.post("/api/connection/preview", dependencies=[Depends(authenticate)])(
        routes_network.connection_preview
    )
    router.post("/api/connection/prepare", dependencies=[Depends(authenticate)])(
        routes_network.connection_prepare
    )
    router.post("/api/connection/apply", dependencies=[Depends(authenticate)])(
        routes_network.connection_apply
    )
    router.post("/api/connection/check", dependencies=[Depends(authenticate)])(
        routes_network.connection_check
    )
    router.post("/api/connection/cancel", dependencies=[Depends(authenticate)])(
        routes_network.connection_cancel
    )
    router.post("/api/connection/stop", dependencies=[Depends(authenticate)])(
        routes_network.connection_stop
    )
    router.post("/api/connection/start", dependencies=[Depends(authenticate)])(
        routes_network.connection_start
    )
    router.get("/api/network/policy", dependencies=[Depends(authenticate)])(
        routes_network.network_policy
    )
    router.post("/api/network/policy", dependencies=[Depends(authenticate)])(
        routes_network.network_policy_set
    )
    router.get("/api/network/catalog", dependencies=[Depends(authenticate)])(
        routes_network.network_catalog
    )
    router.post("/api/network/catalog/refresh", dependencies=[Depends(authenticate)])(
        routes_network.network_catalog_refresh
    )
    router.post(
        "/api/network/catalog/{proxy_id}", dependencies=[Depends(authenticate)]
    )(routes_network.network_catalog_apply)
    router.get("/api/network/proxies", dependencies=[Depends(authenticate)])(
        routes_network.network_proxies
    )
    router.post("/api/network/proxies/check", dependencies=[Depends(authenticate)])(
        routes_network.network_proxies_check
    )
    router.post("/api/network/sources", dependencies=[Depends(authenticate)])(
        routes_network.network_sources
    )
    router.post("/api/network/sources/list", dependencies=[Depends(authenticate)])(
        routes_network.network_sources_list
    )
    router.post("/api/network/github-token", dependencies=[Depends(authenticate)])(
        routes_network.network_github_token
    )
    router.post("/api/network/parse-link", dependencies=[Depends(authenticate)])(
        routes_network.network_parse_link
    )
    router.post("/api/network/test", dependencies=[Depends(authenticate)])(
        routes_network.network_test
    )
    router.post("/api/auth/phone", dependencies=[Depends(authenticate)])(
        routes_accounts.phone
    )
    router.post("/api/auth/code", dependencies=[Depends(authenticate)])(
        routes_accounts.code
    )
    router.post("/api/auth/password", dependencies=[Depends(authenticate)])(
        routes_accounts.password
    )
    router.post("/api/auth/logout", dependencies=[Depends(authenticate)])(
        routes_accounts.logout
    )
    router.post("/api/auth/forget", dependencies=[Depends(authenticate)])(
        routes_accounts.forget_session
    )
    router.get("/api/account/sessions", dependencies=[Depends(authenticate)])(
        routes_accounts.account_sessions
    )
    router.post("/api/account/sessions/end", dependencies=[Depends(authenticate)])(
        routes_accounts.end_account_session
    )
    router.post("/api/account/password", dependencies=[Depends(authenticate)])(
        routes_accounts.change_account_password
    )
    router.get("/api/dialogs", dependencies=[Depends(authenticate)])(
        routes_chats.dialogs
    )
    router.post("/api/targets", dependencies=[Depends(authenticate)])(
        routes_chats.target
    )
    router.post("/api/targets/batch", dependencies=[Depends(authenticate)])(
        routes_chats.targets_batch
    )
    router.post("/api/targets/priority", dependencies=[Depends(authenticate)])(
        routes_chats.target_priority
    )
    router.post(
        "/api/targets/ignore-unconfirmed", dependencies=[Depends(authenticate)]
    )(routes_chats.ignore_sources)
    router.delete("/api/targets/{chat_id}", dependencies=[Depends(authenticate)])(
        routes_chats.target_remove
    )
    router.post("/api/capture", dependencies=[Depends(authenticate)])(
        routes_chats.capture
    )
    router.post("/api/media/queue/clear", dependencies=[Depends(authenticate)])(
        routes_chats.clear_media_queue
    )
    router.post("/api/recording", dependencies=[Depends(authenticate)])(
        routes_chats.set_recording
    )
    router.get("/api/scope", dependencies=[Depends(authenticate)])(
        routes_chats.get_scope
    )
    router.post("/api/scope", dependencies=[Depends(authenticate)])(
        routes_chats.set_scope
    )
    router.post("/api/recheck", dependencies=[Depends(authenticate)])(
        routes_chats.set_recheck
    )
    router.get("/api/evidence", dependencies=[Depends(authenticate)])(
        routes_evidence.get_evidence
    )
    router.post("/api/evidence", dependencies=[Depends(authenticate)])(
        routes_evidence.set_evidence
    )
    router.post("/api/evidence/gateway", dependencies=[Depends(authenticate)])(
        routes_evidence.set_gateway_log
    )
    router.delete("/api/evidence/gateway", dependencies=[Depends(authenticate)])(
        routes_evidence.remove_gateway_log
    )
    router.post("/api/evidence/anchor", dependencies=[Depends(authenticate)])(
        routes_evidence.evidence_anchor
    )
    router.get("/api/source-check", dependencies=[Depends(authenticate)])(
        routes_evidence.get_source_check
    )
    router.get("/api/mode", dependencies=[Depends(authenticate)])(
        routes_evidence.get_mode
    )
    router.patch("/api/mode", dependencies=[Depends(authenticate)])(
        routes_evidence.change_mode
    )
    router.post("/api/source-check", dependencies=[Depends(authenticate)])(
        routes_evidence.run_source_check
    )
    router.get("/api/replica", dependencies=[Depends(authenticate)])(
        routes_evidence.get_replica
    )
    router.get("/api/health", dependencies=[Depends(authenticate)])(
        routes_evidence.get_health
    )
    router.get("/api/setup", dependencies=[Depends(authenticate)])(
        routes_evidence.get_setup
    )
    router.post("/api/setup", dependencies=[Depends(authenticate)])(
        routes_evidence.apply_setup
    )
    router.post("/api/setup/skip", dependencies=[Depends(authenticate)])(
        routes_evidence.skip_setup
    )
    router.post("/api/replica", dependencies=[Depends(authenticate)])(
        routes_evidence.set_replica
    )
    router.get("/api/alerts", dependencies=[Depends(authenticate)])(
        routes_evidence.get_alerts
    )
    router.post("/api/alerts", dependencies=[Depends(authenticate)])(
        routes_evidence.set_alerts
    )
    router.post("/api/alerts/test", dependencies=[Depends(authenticate)])(
        routes_evidence.test_alerts
    )
    router.post("/api/replica/sync", dependencies=[Depends(authenticate)])(
        routes_evidence.replica_sync
    )
    router.post("/api/replica/test", dependencies=[Depends(authenticate)])(
        routes_evidence.replica_test
    )
    router.get("/api/replica/key", dependencies=[Depends(authenticate)])(
        routes_evidence.replica_key
    )
    router.post("/api/monitoring", dependencies=[Depends(authenticate)])(
        routes_chats.monitoring
    )
    router.post("/api/collector/{action}", dependencies=[Depends(authenticate)])(
        routes_chats.control
    )
    router.post("/api/snapshot", dependencies=[Depends(authenticate)])(
        routes_chats.snapshot
    )
    router.get("/api/history", dependencies=[Depends(authenticate)])(
        routes_chats.history_status
    )
    router.post("/api/history/{action}", dependencies=[Depends(authenticate)])(
        routes_chats.history_action
    )
    router.get("/api/history/report", dependencies=[Depends(authenticate)])(
        routes_chats.history_report
    )
    router.get("/api/parameters", dependencies=[Depends(authenticate)])(
        routes_chats.get_parameters
    )
    router.post("/api/parameters", dependencies=[Depends(authenticate)])(
        routes_chats.set_parameters
    )
    app.state.save_parameters = ctx.save_parameters
    router.get("/api/chats", dependencies=[Depends(authenticate)])(routes_chats.chats)
    router.post("/api/interactions/preview", dependencies=[Depends(authenticate)])(
        routes_chats.interaction_preview
    )
    router.post("/api/interactions", dependencies=[Depends(authenticate)])(
        routes_chats.interaction_action
    )
    router.post("/api/interactions/read-only", dependencies=[Depends(authenticate)])(
        routes_chats.interaction_read_only
    )
    router.get("/api/interactions/{request_id}", dependencies=[Depends(authenticate)])(
        routes_chats.interaction_state
    )
    router.get("/api/secret-chats", dependencies=[Depends(authenticate)])(
        routes_secret_chats.view
    )
    router.post("/api/secret-chats/settings", dependencies=[Depends(authenticate)])(
        routes_secret_chats.update_settings
    )
    router.post("/api/secret-chats", dependencies=[Depends(authenticate)])(
        routes_secret_chats.create
    )
    router.post("/api/secret-chats/{chat_id}/accept", dependencies=[Depends(authenticate)])(
        routes_secret_chats.accept
    )
    router.post("/api/secret-chats/{chat_id}/messages", dependencies=[Depends(authenticate)])(
        routes_secret_chats.send
    )
    router.post("/api/secret-chats/{chat_id}/close", dependencies=[Depends(authenticate)])(
        routes_secret_chats.close
    )
    router.get("/api/account/profile", dependencies=[Depends(authenticate)])(
        routes_accounts.account_read
    )
    router.post("/api/account/profile", dependencies=[Depends(authenticate)])(
        routes_accounts.account_profile
    )
    router.post("/api/account/privacy", dependencies=[Depends(authenticate)])(
        routes_accounts.account_privacy
    )
    router.post("/api/account/avatar", dependencies=[Depends(authenticate)])(
        routes_accounts.account_avatar
    )
    router.delete("/api/account/avatar", dependencies=[Depends(authenticate)])(
        routes_accounts.account_avatar_remove
    )
    router.get("/api/account/avatar", dependencies=[Depends(authenticate)])(
        routes_accounts.account_avatar_view
    )
    router.post("/api/account/global-privacy", dependencies=[Depends(authenticate)])(
        routes_accounts.account_global
    )
    router.get("/api/opsec", dependencies=[Depends(authenticate)])(
        routes_documentation.opsec_view
    )
    router.post("/api/opsec/check", dependencies=[Depends(authenticate)])(
        routes_documentation.opsec_check
    )
    router.post("/api/opsec/settings", dependencies=[Depends(authenticate)])(
        routes_documentation.opsec_settings
    )
    router.get("/api/protocol", dependencies=[Depends(authenticate)])(
        routes_documentation.action_protocol_view
    )
    router.get("/api/protocol.html", dependencies=[Depends(authenticate)])(
        routes_documentation.action_protocol_page
    )
    router.get("/api/documentation", dependencies=[Depends(authenticate)])(
        routes_documentation.documentation_list
    )
    router.post("/api/documentation", dependencies=[Depends(authenticate)])(
        routes_documentation.documentation_start
    )
    router.get("/api/documentation/{session_id}", dependencies=[Depends(authenticate)])(
        routes_documentation.documentation_view
    )
    router.post(
        "/api/documentation/{session_id}/package", dependencies=[Depends(authenticate)]
    )(routes_documentation.documentation_package_choice)
    router.post(
        "/api/documentation/{session_id}/{action}", dependencies=[Depends(authenticate)]
    )(routes_documentation.documentation_control)
    router.delete(
        "/api/documentation/{session_id}", dependencies=[Depends(authenticate)]
    )(routes_documentation.documentation_delete)
    router.post(
        "/api/documentation/{session_id}/marks/new",
        dependencies=[Depends(authenticate)],
    )(routes_documentation.documentation_mark)
    router.put(
        "/api/documentation/{session_id}/marks/{mark_id}",
        dependencies=[Depends(authenticate)],
    )(routes_documentation.documentation_mark_edit)
    router.delete(
        "/api/documentation/{session_id}/marks/{mark_id}",
        dependencies=[Depends(authenticate)],
    )(routes_documentation.documentation_mark_delete)
    router.get(
        "/api/documentation/{session_id}/keys.json",
        dependencies=[Depends(authenticate)],
    )(routes_documentation.documentation_keys)
    router.put(
        "/api/documentation/{session_id}/appearance",
        dependencies=[Depends(authenticate)],
    )(routes_documentation.documentation_appearance)
    router.get(
        "/api/documentation/{session_id}/package.zip",
        dependencies=[Depends(authenticate)],
    )(routes_documentation.documentation_package)
    router.get(
        "/api/documentation/{session_id}/document.{suffix}",
        dependencies=[Depends(authenticate)],
    )(routes_documentation.documentation_document)
    router.get("/api/chats/{chat_id}/messages", dependencies=[Depends(authenticate)])(
        routes_chats.chat_messages
    )
    router.get("/api/chats/{chat_id}/authors", dependencies=[Depends(authenticate)])(
        routes_chats.chat_authors
    )
    router.get("/api/chats/{chat_id}/profile", dependencies=[Depends(authenticate)])(
        routes_chats.chat_profile
    )
    router.post("/api/chats/{chat_id}/profile", dependencies=[Depends(authenticate)])(
        routes_chats.chat_profile_save
    )
    router.get("/api/chats/{chat_id}/people", dependencies=[Depends(authenticate)])(
        routes_chats.people_list
    )
    router.get(
        "/api/chats/{chat_id}/people/{user_id}", dependencies=[Depends(authenticate)]
    )(routes_chats.person_timeline)
    router.post("/api/chats/{chat_id}/dossier", dependencies=[Depends(authenticate)])(
        routes_chats.dossier_switch
    )
    router.get("/api/chats/{chat_id}/dossier", dependencies=[Depends(authenticate)])(
        routes_chats.dossier_view
    )
    router.get(
        "/api/chats/{chat_id}/dossier/export", dependencies=[Depends(authenticate)]
    )(routes_chats.dossier_export)
    router.post(
        "/api/chats/{chat_id}/dossier/export", dependencies=[Depends(authenticate)]
    )(routes_chats.dossier_export_encrypted)
    router.get("/api/witness", dependencies=[Depends(authenticate)])(
        routes_witness.witness_state
    )
    router.post("/api/witness/tokens", dependencies=[Depends(authenticate)])(
        routes_witness.witness_token
    )
    router.delete(
        "/api/witness/tokens/{token_id}", dependencies=[Depends(authenticate)]
    )(routes_witness.witness_revoke)
    router.get("/api/witness/head")(routes_witness.witness_head)
    router.get("/api/notifications", dependencies=[Depends(authenticate)])(
        routes_chats.notifications
    )
    router.get("/api/chats/{chat_id}/scale", dependencies=[Depends(authenticate)])(
        routes_chats.chat_scale
    )
    router.get("/api/avatar/{peer_id}", dependencies=[Depends(authenticate)])(
        routes_chats.avatar
    )
    router.get("/api/account-export", dependencies=[Depends(authenticate)])(
        routes_export.account_export_jobs
    )
    router.post("/api/account-export/start", dependencies=[Depends(authenticate)])(
        routes_export.account_export_start
    )
    router.post("/api/account-export/preflight", dependencies=[Depends(authenticate)])(
        routes_export.account_export_preflight
    )
    router.get("/api/account-export/{export_id}", dependencies=[Depends(authenticate)])(
        routes_export.account_export_status
    )
    router.post(
        "/api/account-export/{export_id}/pause", dependencies=[Depends(authenticate)]
    )(routes_export.account_export_pause)
    router.post(
        "/api/account-export/{export_id}/resume", dependencies=[Depends(authenticate)]
    )(routes_export.account_export_resume)
    router.post(
        "/api/account-export/{export_id}/finish", dependencies=[Depends(authenticate)]
    )(routes_export.account_export_finish)
    ctx.account_downloads = {}
    app.state.account_downloads = ctx.account_downloads
    router.delete(
        "/api/account-export/{export_id}", dependencies=[Depends(authenticate)]
    )(routes_export.account_export_remove)
    router.post(
        "/api/account-export/{export_id}/ticket", dependencies=[Depends(authenticate)]
    )(routes_export.account_export_ticket)
    router.get("/api/account-export/{export_id}/download")(
        routes_export.account_export_download
    )
    router.post(
        "/api/account-export/{export_id}/disclosure/preview",
        dependencies=[Depends(authenticate)],
    )(routes_export.disclosure_preview)
    router.post(
        "/api/account-export/{export_id}/disclosure",
        dependencies=[Depends(authenticate)],
    )(routes_export.disclosure_create)
    router.post(
        "/api/account-export/{export_id}/disclosures/{disclosure_id}/ticket",
        dependencies=[Depends(authenticate)],
    )(routes_export.disclosure_ticket)
    router.get("/api/account-export/{export_id}/disclosures/{disclosure_id}/download")(
        routes_export.disclosure_download
    )
    router.post("/api/chat-export/start", dependencies=[Depends(authenticate)])(
        routes_export.chat_export_start
    )
    router.get("/api/report-guidance", dependencies=[Depends(authenticate)])(
        routes_export.report_guidance_catalog
    )
    router.get("/api/report-options", dependencies=[Depends(authenticate)])(
        routes_export.get_report_options
    )
    router.post("/api/report-options", dependencies=[Depends(authenticate)])(
        routes_export.set_report_options
    )
    router.get("/api/report-profiles", dependencies=[Depends(authenticate)])(
        routes_export.get_report_profiles
    )
    router.post("/api/report-profiles", dependencies=[Depends(authenticate)])(
        routes_export.save_report_profile
    )
    router.delete(
        "/api/report-profiles/{profile_id}", dependencies=[Depends(authenticate)]
    )(routes_export.delete_report_profile)
    router.get("/report-preview.css")(routes_export.report_preview_css)
    router.post("/api/report-design-preview", dependencies=[Depends(authenticate)])(
        routes_export.report_preview
    )
    router.post("/api/report-preview", dependencies=[Depends(authenticate)])(
        routes_export.preview_report
    )
    ctx.chat_export_owners = {}
    router.get("/api/chat-export/{export_id}", dependencies=[Depends(authenticate)])(
        routes_export.chat_export_poll
    )
    router.post(
        "/api/chat-export/{export_id}/cancel", dependencies=[Depends(authenticate)]
    )(routes_export.chat_export_cancel)
    router.get(
        "/api/chat-export/{export_id}/download", dependencies=[Depends(authenticate)]
    )(routes_export.chat_export_download)
    router.get("/api/checkpoint", dependencies=[Depends(authenticate)])(
        routes_evidence.get_checkpoint
    )
    router.get("/api/run-receipt", dependencies=[Depends(authenticate)])(
        routes_evidence.get_run_receipt
    )
    router.get("/api/assurance")(routes_evidence.assurance_statement)
    router.get("/api/anchor-request", dependencies=[Depends(authenticate)])(
        routes_evidence.anchor_request
    )
    router.post("/api/verify", dependencies=[Depends(authenticate)])(
        routes_evidence.verify
    )
    app.state.build_export = ctx.build_export
    router.get("/api/export/{fmt}", dependencies=[Depends(authenticate)])(
        routes_export.export
    )
    router.post("/api/export/{fmt}", dependencies=[Depends(authenticate)])(
        routes_export.export_encrypted
    )
    router.post("/api/handover", dependencies=[Depends(authenticate)])(
        routes_export.export_handover
    )
    router.get("/api/exports/history", dependencies=[Depends(authenticate)])(
        routes_export.prepared_exports
    )
    ctx.prepared_tickets = {}
    router.post(
        "/api/exports/{export_id}/ticket", dependencies=[Depends(authenticate)]
    )(routes_export.export_ticket)
    router.get("/api/exports/{export_id}/download")(routes_export.export_again)
    router.post("/api/privacy/reveal", dependencies=[Depends(authenticate)])(
        routes_chats.reveal_secret
    )
    router.get("/api/media/{digest}", dependencies=[Depends(authenticate)])(
        routes_chats.media
    )
    app.include_router(router)
    router = APIRouter()
    register_board(app, authenticate, ctx.profile_id)
    register_webhooks(app, authenticate, ctx.profile_id)
    register_search(app, authenticate, ctx.profile_id)
    register_storage(app, authenticate, ctx.require_live)
    register_capture(app, authenticate, ctx.require_live)
    register_conversation(app, authenticate, ctx.require_live, ctx.visible_chats)
    register_translation(app, authenticate, ctx.require_live, ctx.visible_chats)
    register_search_record(app, authenticate, ctx.visible_chats)
    register_subject(app, authenticate, ctx.require_live, ctx.operation, ctx.root / "media")
    register_undercover(app, authenticate, ctx.require_live)
    register_presence(app, authenticate, ctx.require_live, ctx.operation)
    register_qr(app, authenticate, ctx.require_live, ctx.visible_chats, ctx.root / "media")
    register_watchlists(app, authenticate, ctx.require_live, ctx.visible_chats)
    register_channel_graph(app, authenticate, ctx.require_live)
    register_webapp(app, authenticate, ctx.require_live, ctx.visible_chats)
    app.state.extensions = extensions.load(
        extensions.Context(
            app,
            authenticate,
            extensions.JournalReader(lambda: app.state.store),
            lambda: extensions.workspace_goal(app.state.store),
            ctx.require_chat,
            ctx.recheck_export_scope,
        )
    )
    router.get("/api/extensions", dependencies=[Depends(authenticate)])(
        routes_chats.extension_list
    )
    app.include_router(router)
    router = APIRouter()
    if ctx.allow_profiles:
        router.post("/api/access/login")(routes_access.access_login)
        router.post("/api/access/logout")(routes_access.access_logout)
        router.get("/api/access/me")(routes_access.access_me)
        router.get("/api/access", dependencies=[Depends(authenticate)])(
            routes_access.access_overview
        )
        router.post("/api/access/grants", dependencies=[Depends(authenticate)])(
            routes_access.access_issue
        )
        router.patch(
            "/api/access/grants/{grant_id}", dependencies=[Depends(authenticate)]
        )(routes_access.access_change)
        router.delete(
            "/api/access/grants/{grant_id}", dependencies=[Depends(authenticate)]
        )(routes_access.access_revoke)
        router.delete(
            "/api/access/sessions/{session_id}", dependencies=[Depends(authenticate)]
        )(routes_access.access_end_session)
        router.post("/api/access/admin", dependencies=[Depends(authenticate)])(
            routes_access.access_admin
        )
        router.post("/api/access/token", dependencies=[Depends(authenticate)])(
            routes_access.access_rotate_token
        )
        router.get("/api/access/console", dependencies=[Depends(authenticate)])(
            routes_access.access_console
        )
        from ..archive_api import register as register_archive
        from ..showcase import register as register_showcase

        app.include_router(router)
        router = APIRouter()
        register_showcase(app, authenticate)
        register_archive(app, authenticate)
        from ..analysis_api import register as register_analysis

        register_analysis(app, authenticate)
        from ..media_analysis_api import register as register_media_analysis

        register_media_analysis(app, authenticate)
        app.mount("/profiles", ProfileDispatch(app), name="profiles")
    register_settings(
        app,
        authenticate,
        ctx.require_live,
        ctx.operation,
        ctx.save_evidence,
        ctx.save_capture,
    )
    static = PanelFiles(directory=Path(__file__).parent.parent / "static")
    register_panel(app, static)
    app.mount("/", static, name="panel")
    app.add_middleware(RequestSecurity)
