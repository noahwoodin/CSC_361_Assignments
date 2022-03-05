import re
import sys
from helpers import get_cookies, check_http2, uri_parse, get_status, pretty_print_output, socket_connect, socket_send
from output_data_class import ProgramOutput


def get_http_or_https_response(host, protocol, path):
    """
    get_http_or_https_response attempts to connect and send a request to the host and then parses the response for
    status code, cookies, and password protection. In the case of a redirect get_http_or_https_response calls itself
    recursively with the new host, protocol and path.
    :param host: the host to connect to
    :param protocol: the protocol to use
    :param path: the path to use
    :return output: A ProgramOutput object with http support, cookies and password protection details
    """
    if protocol == "http":
        port = 80
    else:
        port = 443

    sock = socket_connect(host, port)

    response = socket_send(sock, host, path)

    status_code = get_status(response)

    redirect = [301, 302]
    successful_communication = [200, 404, 503, 401]

    if status_code in redirect:
        new_uri = re.search(r'Location: (.*)', response).group(1)

        host, protocol, path = uri_parse(new_uri)

        print("Redirect status code {} received".format(status_code))
        print("Following new uri with host={}, path={}".format(host, path))
        return get_http_or_https_response(host, protocol, path)

    elif status_code in successful_communication:
        output = ProgramOutput([])

        if status_code == 401:
            output.password_protected = True

        if port == 443:
            output.http2_support = check_http2(host)

        output.cookies = get_cookies(response)

        return output

    else:
        print("Received an unexpected http/https status code: {}".format(status_code))
        print("Exiting gracefully")
        sys.exit()


def main():
    """
    Takes a uri as a program argument and determines if the site supports http2, whether it is password protected
    as well as records the sites cookies
    """
    if len(sys.argv) < 2:
        print("No input given")
        print("Exiting gracefully")
        sys.exit()

    uri_given = sys.argv[1]
    print("URI argument: {}".format(uri_given))
    host, protocol, path = uri_parse(uri_given)
    program_output = get_http_or_https_response(host, protocol, path)
    pretty_print_output(program_output, uri_given)


if __name__ == '__main__':
    main()
