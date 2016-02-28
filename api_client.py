import logging
import requests

from ksi.keys import Keys
from ksi.ksi_client import KSIClient
from ksi.dao_mongo import DAOMongoFactory, DAOMongoClient
from ksi.dao import factory

#
# REST API client example.
# This file is executable as a "standalone" script.
#

logging.basicConfig(level=logging.DEBUG)

# Filter messages to come only from the client's logger
for handler in logging.root.handlers:
    handler.addFilter(logging.Filter("ksi.ksi_client.KSIClient"))


if __name__ == "__main__":

    # dao_factory = factory(DAOMemoryFactory)
    dao_factory = factory(DAOMongoFactory)
    client = KSIClient(None, dao_factory.get_client(), keys=Keys(l=8, seed=b'SEED2'), ID_C_str="client2",
                       api_user="client2", api_password="password2", api_ID_S="server")

    client.sign(b'EFGH', use_rest_api=True)
    dao_client = dao_factory.get_client()  # type: DAOMongoClient

    # The client and server DAO don't share user certificates (so we would have an error
    # KSIErrorCode.UNKNOWN_CERTIFICATE)
    # assert dao_client.signatures == {}
    r = requests.get('http://localhost:5000/ksi/api/v0.1/signed')
    assert str(client.certificate.id_client) in r.json()['signed_timestamps']
