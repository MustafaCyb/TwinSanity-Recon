"""
Compatibility helpers for Jinja template rendering across Starlette versions.
"""
import inspect
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates


_TEMPLATE_RESPONSE_ACCEPTS_REQUEST = (
    "request" in inspect.signature(Jinja2Templates.TemplateResponse).parameters
)


def template_response(
    templates: Jinja2Templates,
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    **kwargs: Any,
):
    """Render a template with either the old or new Starlette TemplateResponse API."""
    template_context = dict(context or {})
    template_context.setdefault("request", request)

    if _TEMPLATE_RESPONSE_ACCEPTS_REQUEST:
        return templates.TemplateResponse(
            request=request,
            name=name,
            context=template_context,
            **kwargs,
        )

    return templates.TemplateResponse(
        name=name,
        context=template_context,
        **kwargs,
    )
