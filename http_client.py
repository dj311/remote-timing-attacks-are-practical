HTTP_METHODS = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
}


HTTP_HEADERS = {
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Authorization",
    "Expect",
    "From",
    "Host",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "TE",
    "User-Agent",
}


def make_http_request(method, uri, headers=None, body=None, http_version="HTTP/1.1"):
    if headers is None:
        headers = {}
    if body is None:
        body = ""

    assert method in HTTP_METHODS
    assert all([header in HTTP_HEADERS for header in headers.keys()])

    header_lines = [
        "{name}: {value}".format(name, value) for name, value in headers.items()
    ]
    header_str = "\n".join(header_lines)

    request = u"""
{method} {uri} {http_version}
{header}

{body}
""".format(
        method=method, uri=uri, http_version=http_version, header=header_str, body=body
    )

    return bytes(request, encoding="utf8")
