

from edge.install_gg import SslCreds


if __name__ == "__main__":

    creds = SslCreds(
        dest_directory="../garbage/secrets",
        base_name="testThing"
    )

    creds.create_private_key_and_csr()
    csr = creds.get_csr()
    print(csr)
