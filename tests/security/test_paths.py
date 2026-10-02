# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Path fuzzing through the full middleware chain: deterministic mutations of every admin route's sample path.

Invariant: a viewer's write never reaches the recording view, and the answer is the gate's refusal, a 404, a redirect
or a 400 — never 2xx. Anonymous callers never reach a view that does not authenticate them itself.
"""

import pytest

from tests.security import urls
from tests.security.contract import WRITES

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.security.urls")]

# Every admin route but the staff baseline (any staff user may write there).
ADMIN_PATHS = (
    urls.RW_READ,
    urls.RW_WRITE,
    urls.READ_ONLY,
    urls.WRITE_ONLY,
    urls.EXPORT,
    urls.DEFAULT_AUTH,
    urls.ALLOW_ANY,
    urls.FUNCTION,
    urls.PII_DOWNLOAD,
    urls.UNMAPPED,
    urls.BASIC_JWT,
    urls.SUBCLASS_JWT,
)
NOT_SELF_AUTH_PATHS = (
    urls.DEFAULT_AUTH,
    urls.ALLOW_ANY,
    urls.FUNCTION,
    urls.PII_DOWNLOAD,
    urls.BASIC_JWT,
    urls.SUBCLASS_JWT,
)
CYRILLIC_A = "а"


def _parts(path: str) -> tuple[str, str]:
    """The first segment and the rest of the path (with its trailing slash)."""
    first, rest = path.strip("/").split("/", 1)
    return first, rest + "/"


def _encode_first_letters(path: str) -> str:
    return "/".join(f"%{ord(segment[0]):02x}{segment[1:]}" if segment else "" for segment in path.split("/"))


MUTATIONS = {
    "no_trailing_slash": lambda p: p[:-1],
    "double_slash_start": lambda p: "/" + p,
    "double_slash_inside": lambda p: "/{}//{}".format(*_parts(p)),
    "encoded_slash": lambda p: "/{}%2F{}".format(*_parts(p)),
    "encoded_letters": _encode_first_letters,
    "upper_case": str.upper,
    "path_param_last": lambda p: p[:-1] + ";x=1/",
    "path_param_first": lambda p: "/{};x=1/{}".format(*_parts(p)),
    "dot_segment": lambda p: "/{}/./{}".format(*_parts(p)),
    "dot_dot_segment": lambda p: "/{}/x/../{}".format(*_parts(p)),
    "encoded_dot_dot": lambda p: "/{}/x/%2e%2e/{}".format(*_parts(p)),
    "nul_byte": lambda p: p + "%00",
    "nul_byte_inside": lambda p: p[:-1] + "%00/",
    "cyrillic_look_alike": lambda p: p.replace("a", CYRILLIC_A, 1),
    "format_suffix": lambda p: p[:-1] + ".json",
    "format_suffix_slash": lambda p: p[:-1] + ".json/",
    "format_query": lambda p: p + "?format=json",
    "fragment": lambda p: p + "#frag",  # the client drops the fragment, as browsers do: the gate sees the path
    "unchanged": lambda p: p,
}
ALLOWED_STATUSES = {301, 308, 400, 404}


def assert_never_served(response, ran: list) -> None:
    """The view never ran; a 401/403 is the gate's own (it names an issue, a view's refusal does not)."""
    assert ran == []
    if response.status_code in (401, 403):
        assert response.json()["details"], "a 401/403 that is not the gate's"
        return
    assert response.status_code in ALLOWED_STATUSES


@pytest.fixture
def viewer(principal):
    return principal("viewer")


@pytest.mark.parametrize("mutation", MUTATIONS)
@pytest.mark.parametrize("path", ADMIN_PATHS)
def test_viewer_write_on_a_mutated_path_never_runs(client, viewer, ran, path, mutation):
    for method in WRITES:
        assert_never_served(client.generic(method, MUTATIONS[mutation](path), **viewer), ran)


@pytest.mark.parametrize("mutation", ["unchanged", "encoded_slash", "encoded_letters", "format_query"])
@pytest.mark.parametrize("path", ADMIN_PATHS)
def test_resolving_mutations_reach_the_gate(client, viewer, path, mutation):
    """The fuzzing is not vacuous: these mutations resolve to the view, and the gate refuses them itself."""
    response = client.post(MUTATIONS[mutation](path), **viewer)
    assert response.status_code in (401, 403)
    assert response.json()["details"]


@pytest.mark.parametrize("path", ADMIN_PATHS)
def test_method_override_is_not_honoured(client, viewer, ran, path):
    assert_never_served(client.post(path, HTTP_X_HTTP_METHOD_OVERRIDE="GET", **viewer), ran)
    assert_never_served(client.post(path, {"_method": "GET"}, **viewer), ran)


@pytest.mark.parametrize("mutation", MUTATIONS)
@pytest.mark.parametrize("path", NOT_SELF_AUTH_PATHS)
def test_anonymous_on_a_mutated_path_never_runs(client, ran, path, mutation):
    for method in ("GET", *WRITES):
        assert_never_served(client.generic(method, MUTATIONS[mutation](path)), ran)
