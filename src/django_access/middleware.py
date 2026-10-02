# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``AccessGateMiddleware``: decides every resolved request before its view runs (``services.gate``).

Append it after the authentication middleware. ``process_view`` runs only after a successful resolve, so an unknown
path stays a 404. ``ACCESS_GATE_MODE`` = ``enforce`` (default) | ``observe`` (log refusals, let through) | ``off``.
"""

import logging

from django.http import HttpRequest, HttpResponse

from django_access.services import gate

logger = logging.getLogger("django_access.gate")


class AccessGateMiddleware:
    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        decision = getattr(request, "_access_decision", None)
        if decision is not None and decision.bypass:
            self._record_bypass(request, decision, response.status_code)
        return response

    def process_view(self, request: HttpRequest, view_func, view_args, view_kwargs) -> HttpResponse | None:
        current = gate.mode()
        if current == gate.OFF:
            return None
        try:
            decision = gate.decide(request, view_func)
        except Exception:
            debug_id = gate.new_debug_id()
            logger.exception("Gate decision failed [%s]", debug_id)
            return None if current == gate.OBSERVE else gate.internal_error(debug_id)
        request._access_decision = decision
        if decision.allow:
            return None
        if current == gate.OBSERVE:
            gate.log_refusal(request, decision)
            return None
        return gate.refusal(decision)

    @staticmethod
    def _record_bypass(request: HttpRequest, decision: gate.Decision, status: int) -> None:
        """An audit failure must not change the response: the view already ran."""
        try:
            gate.record_bypass(request, decision, status)
        except Exception:
            logger.exception("Gate bypass audit failed [%s]", gate.new_debug_id())
