import re
import socket
import ssl
import sys

from output_data_class import CookieInfo


def get_status(response):
    """
    get_status takes the server response and extracts the http/https status code from the header
    :param response: http/https response from the server
    :return status_code: the response status code from the server
    """
    response_lines = response.splitlines()

    first_header = response_lines[0].split()

    status_code = first_header[1]
    print("{} status received".format(status_code))
    return int(status_code)


def get_cookies(response):
    """
    get_cookies takes the server response and extracts the cookies from the response
    :param response: http/https response from the server
    :return resulting_cookies: a list of CookieInfo objects
    """
    print("Parsing cookies")
    response_lines = response.splitlines()
    cookies = [x for x in response_lines if x.startswith("Set-Cookie")]
    resulting_cookies = []
    for cookie in cookies:
        cookie_object = CookieInfo(name=re.search(r'Set-Cookie: (.*?);', cookie).group(1))
        expires = re.search(r'expires=(.*?);', cookie)
        domain = re.search(r'domain=(.*?);', cookie)
        if expires:
            cookie_object.expires = expires.group(1)
        if domain:
            cookie_object.domain = domain.group(1)
        resulting_cookies.append(cookie_object)
    print("{} cookies found".format(len(resulting_cookies)))
    return resulting_cookies


def uri_parse(uri):
    """
    uri_parse takes a uri string and breaks it into protocol, host and path. If protocol and path do not exist in the
    string they take on None and '/' respectively
    :param uri: the uri string to be parsed
    :return host, protocol, path: the host, protocol and path extracted from the uri
    """
    print("Parsing uri")
    protocol = None
    path = '/'

    uri = uri.split("://")

    # If protocol included
    if len(uri) > 1:
        protocol = uri[0]
        uri = uri[1]
    else:
        uri = uri[0]

    # Strip trailing spaces, newlines and /
    uri = uri.strip().strip('/')

    # If path is included
    possible_path = re.search(r'/(.*)', uri)
    if possible_path:
        path = '/' + possible_path.group(1) + '/'

    uri = uri.split('/')
    host = uri[0]
    print("host={}, protocol={}, path={}".format(host, protocol, path))
    return host, protocol, path


def check_http2(host):
    """
    check_http2 uses the method described in tutorial to check if a host supports http2
    :param host: the host to check for http2 support
    :return Boolean: True is http2 supported, else False
    """
    print("Checking for http2 support")
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2', 'http/1.1'])

    try:
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
        conn.connect((host, 443))
    except socket.gaierror:
        print("Connection exception while checking for http2 support")
        return False

    pp = conn.selected_alpn_protocol()

    return pp == "h2"


def socket_connect(host, port):
    """
    socket_connect creates a new socket and connects to it using host and port
    :param host: the host to connect to
    :param port: the port to use
    :return sock: the new socket
    """
    print("Creating a socket with host={} and port={}".format(host, port))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket:
        print("Exception while creating socket")
        print("Exiting gracefully")
        sys.exit()

    try:
        sock.connect((host, port))
    except socket.gaierror:
        print("Exception while connecting to socket")
        print("Exiting gracefully")
        sys.exit()

    if port == 443:
        try:
            sock = ssl.wrap_socket(sock)
        except ssl.SSLError:
            print("Exception while wrapping socket")
            print("Exiting gracefully")
            sys.exit()
    return sock


def socket_send(sock, host, path):
    """
    socket_send sends a HEAD request using the given socket
    :param sock: the socket to use
    :param host: the host to use
    :param path: the path to use
    :return response: the response from the host
    """
    message = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    print("Sending a request with host={}, path={}, message={}".format(host, path, message))
    sock.send(message)
    response = sock.recv(4096).decode()
    print("---Response header---")
    print(response)
    return response


def pretty_print_output(output, uri):
    """
    pretty_print_output takes a ProgramOutput object and prints its content according to assignment specifications
    :param output: the ProgramOutput object to be printed
    :param uri: the uri that was passed as an argument to the SmartClient.py
    """
    print("")
    print("---MY RESULTS---")
    print("website: {}".format(uri))
    print("1. Supports http2: {}".format("yes" if output.http2_support else "no"))
    print("2. List of Cookies:")
    for cookie in output.cookies:
        print("cookie name: {}, expires time: {}, domain name: {}".format(cookie.name, cookie.expires, cookie.domain))
    print("3. Password-protected: {}".format("yes" if output.password_protected else "no"))
    print("")
