from fastapi import Request


def current_context(request: Request):
    return request.app.state.api_context
