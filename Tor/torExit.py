from datetime import datetime
import io
import pycurl
import stem.process
from stem.util import term
from stem import CircStatus
from stem.control import Controller

SOCKS_PORT = 7000

def query(url):
    """
    Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
    """

    output = io.BytesIO()

    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    query.setopt(pycurl.WRITEFUNCTION, output.write)

    try:
        query.perform()
        return output.getvalue()
    except pycurl.error as exc:
        return "Unable to reach %s (%s)" % (url, exc)


def print_bootstrap_lines(line):
    if "Bootstrapped " in line:
        print(term.format(line, term.Color.BLUE))

print(term.format("Starting Tor:\n", term.Attr.BOLD))

tor_process = stem.process.launch_tor_with_config(
    config = {
        'ControlPort': '9051',
        'SocksPort': str(SOCKS_PORT),
        'ExitNodes': '151.80.148.159',
    },
    init_msg_handler = print_bootstrap_lines,
)

print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
print(query("http://3.231.47.87:14741/flag?id=mohanl"))

# get exit node information
with Controller.from_port(port = 9051) as controller:
    controller.authenticate()
    for circ in sorted(controller.get_circuits()):
        if circ.status != CircStatus.BUILT:
            continue
        print("")
        print("Circuit %s (%s)" % (circ.id, circ.purpose))
        for i, entry in enumerate(circ.path):
            div = '+' if (i == len(circ.path) - 1) else '|'
            fingerprint, nickname = entry
            desc = controller.get_network_status(fingerprint, None)
            address = desc.address if desc else 'unknown'
            country = controller.get_info("ip-to-country/%s" % desc.address, 'unknown')

            print(" %s- (%s, %s, country code %s)" %
                  (div, nickname, address, country))

print(datetime.now())
tor_process.kill()
