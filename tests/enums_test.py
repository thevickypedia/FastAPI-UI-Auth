from uiauth.enums import APIEndpoints


def test_endpoint_values():
    assert APIEndpoints.fastapi_error == "/fastapi-error"
    assert APIEndpoints.fastapi_login == "/fastapi-login"
    assert APIEndpoints.fastapi_logout == "/fastapi-logout"
    assert APIEndpoints.fastapi_session == "/fastapi-session"
    assert APIEndpoints.fastapi_verify_login == "/fastapi-verify-login"


def test_all_endpoints_are_strings():
    for endpoint in APIEndpoints:
        assert isinstance(endpoint, str)


def test_all_endpoints_start_with_slash():
    for endpoint in APIEndpoints:
        assert endpoint.startswith("/"), f"{endpoint} does not start with '/'"


def test_all_endpoints_are_unique():
    values = [e.value for e in APIEndpoints]
    assert len(values) == len(set(values))
