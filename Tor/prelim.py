from stem import CircStatus
from stem.control import Controller

with Controller.from_port(port=9051) as controller:
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
            bandwidth = desc.bandwidth if desc else 'unknown'
            country = controller.get_info("ip-to-country/%s" % desc.address, 'unknown')

            print(" %s- (%s, %s, bandwidth = %d, country code %s)" %
                  (div, nickname, address, bandwidth, country))
