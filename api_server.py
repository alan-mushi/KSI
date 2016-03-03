import logging
from flask import Flask, request, abort, jsonify, make_response
from flask.ext.httpauth import HTTPBasicAuth

from ksi.ksi_server import KSIServer
from ksi.ksi_client import KSIClient
from ksi.identifier import Identifier
from ksi.ksi_messages import TimestampRequest, TimestampResponse
from ksi import SIGN_KEY_FORMAT
from ksi.keys import Keys
from ksi.dao_mongo import DAOMongoFactory, DAOMongoServer, clean_databases
from ksi.dao import factory
from ksi.hash import hash_factory
from ksi import API_ROUTE_BASE, IDENTIFIER_BASE_NAME

#
# REST API.
# This file is executable as a "standalone" script.
#

logging.basicConfig(level=logging.INFO)

# Filter messages to come only from the server's logger
# for handler in logging.root.handlers:
#    handler.addFilter(logging.Filter("ksi.ksi_server.KSIServer"))

app = Flask(__name__)
auth = HTTPBasicAuth()
SALT = b'KSI_IS_MAGIC'

dao_factory = factory(DAOMongoFactory)
dao = dao_factory.get_server()  # type: DAOMongoServer

ksi_server = KSIServer(Identifier("server"), dao, filename_private_key="/tmp/private_key." + SIGN_KEY_FORMAT)


def hash_salt(s: str) -> bytes:
    return hash_factory(data=bytes(s, encoding='ascii') + SALT).digest()


# The list of authorized users and their hash/salted passwords (this ought to move to a DB in the future...)
user_dict = {'client': hash_salt('password'), 'client2': hash_salt('password2')}


def callback_log(x: TimestampResponse):
    """
    The callback for the signature, it is actually not _needed_ but if we remove the callback argument to send_sign()
    then it is much harder to test. Thus, we use it as a logger.
    """
    logging.info("Got callback with x: %s", x)
    return x


@auth.verify_password
def verify_password(username: str, password: str) -> bool:
    return username in user_dict and hash_salt(password) == user_dict[username]


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


@app.route(API_ROUTE_BASE + 'sign', methods=['POST'])
@auth.login_required
def sign_request():
    """
    Sign a request, see API reference in the wiki.
    """
    if not request.json or 'x' not in request.json or 'ID_C' not in request.json:
        abort(400)

    req = TimestampRequest.from_json(request.json)

    if str(req.ID_C)[len(IDENTIFIER_BASE_NAME):] != auth.username():
        logging.warning("Wrong signing request: ID_C and username don't match!")
        return make_response(jsonify({'error': 'ID_C and username don\'t match!'}), 401)

    res = ksi_server.get_timestamp_response(req, callback_log)

    return res.to_json(), 201


@app.route(API_ROUTE_BASE + 'signed', methods=["GET"])
def get_signed_timestamps():
    """
    Return all the signed timestamps/requests, see API reference in the wiki.
    """
    res = {}

    for d in dao.get_signed_requests():
        for _k, _v in d.items():
            new_k = _k.replace('#', '.')

            if new_k not in res:
                res[new_k] = {}

            for iso_timestamp, __v in _v.items():
                res[new_k][iso_timestamp] = {msg: str(sig, encoding='ascii') for msg, sig in __v.items()}

    return jsonify({'signed_timestamps': res})


if __name__ == '__main__':
    clean_databases()

    # We add something to the DAO
    client = KSIClient(ksi_server, dao_factory.get_client(), keys=Keys(l=8, seed=b'SEED'),
                       public_key_filename="/tmp/public_key." + SIGN_KEY_FORMAT)

    sig = client.sign(b'ABCD')
    assert client.verify(sig, client.certificate, sig.message) is True

    sig2 = client.sign(b'ABCD')
    assert client.verify(sig2, client.certificate, sig2.message) is True

    # Launch the API
    app.run()
