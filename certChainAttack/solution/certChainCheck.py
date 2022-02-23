#!/usr/bin/python3

from OpenSSL import SSL, crypto
import socket
import certifi
import pem
import fnmatch
import urllib

# Cert Paths
TRUSTED_CERTS_PEM = certifi.where()


def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    # Set up a TLS Connection
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    # Send HTTP Req (initiates TLS Connection)
    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)

    # Get Cert Meta Data from TLS connection
    test_site_certs = s.get_peer_cert_chain()
    s.close()
    return test_site_certs

# Add Any Helper Functions Below

##############################################


'''
This function returns true if the target_domain provides a valid
x509cert and false in case it doesn't or if there's an error.
'''
def x509_cert_chain_check(target_domain: str):
    trusted_certs = pem.parse_file(TRUSTED_CERTS_PEM)
    store = crypto.X509Store()
    # add the root certificates
    for cert in trusted_certs:
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, str(cert))
        store.add_cert(trusted_cert)

    # a list of <OpenSSL.crypto.X509 object> from leaf to root
    cert_chain = get_cert_chain(target_domain)

    host_match = False
    # check host by looking into extension
    for i in range(cert_chain[0].get_extension_count()):
        if "DNS" in cert_chain[0].get_extension(i).__str__():
            extension = cert_chain[0].get_extension(i).__str__()
            dns_list = extension.split(', ')
            for dns in dns_list:
                if fnmatch.fnmatch(target_domain, dns[4:]):
                    # count '.' characters - approved by TA's on piazza @173
                    if dns[4:].count('.') == target_domain.count('.'):
                        host_match = True
                        print(dns[4:])

    if not host_match:
        return False

    # verify the chain
    for i in range(len(cert_chain) - 1, 0, -1):
        # store (X509Store) – The certs which will be trusted for verifications.
        # certificate (X509) – The certificate to be verified.
        store_ctx = crypto.X509StoreContext(store, cert_chain[i])
        try:
            if store_ctx.verify_certificate() != None:
                print(store_ctx.verify_certificate())
                return False
        except crypto.X509StoreContextError as e:
            print(e)
            print(e.certificate)
            return False
        store.add_cert(cert_chain[i])
    # verify the end-entity certificate
    store_ctx = crypto.X509StoreContext(store, cert_chain[0])
    
    try:
        if store_ctx.verify_certificate() != None:
            print(store_ctx.verify_certificate())
            return False
        else:
            return True
    except crypto.X509StoreContextError as e:
        print(e)
        print(e.certificate)
        return False


if __name__ == "__main__":

    # Standalone running to help you test your program
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    print("Certificate for {} verifed: {}".format(
        target_domain, x509_cert_chain_check(target_domain)))
