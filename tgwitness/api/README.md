# Panel API

`app.create_app` constructs an `ApplicationContext` and assembles the application.
Domain modules expose top-level endpoints; each receives its workspace context
through `Depends(current_context)`. Tests can pass `ctx` directly without building
an application. Request models remain importable from `tgwitness.app`.

Context operations hold shared authorization, export and collection helpers.
`lifecycle.py` owns startup and shutdown; `registration.py` preserves route order,
authentication dependencies and the existing optional registrations.

`current_context` reads `request.app.state.api_context`, so profile dispatch uses
the child's state, locks and scope. It does not use a process-global workspace.

Run `tools/test_api_refactor.py` and `tools/test_api_authorization_matrix.py` in an
authorized test environment. The route audit includes FastAPI's nested routers;
checking only top-level `APIRoute` objects can miss included endpoints.
