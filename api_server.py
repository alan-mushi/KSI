import logging
from base64 import standard_b64encode
from flask import Flask, request, abort, jsonify, make_response
from flask.ext.httpauth import HTTPBasicAuth

from ksi.ksi_server import KSIServer
from ksi.ksi_client import KSIClient
from ksi.identifier import Identifier
from ksi.ksi_messages import TimestampRequest, TimestampResponse
from ksi import SIGN_KEY_FORMAT
from ksi.keys import Keys
from ksi.dao_memory import DAOMemoryFactory, DAOMemoryServer
from ksi.dao import factory
from ksi.hash import hash_factory
from ksi import API_ROUTE_BASE

#
# REST API.
# This file is executable as a "standalone" script.
#

app = Flask(__name__)
auth = HTTPBasicAuth()
SALT = b'KSI_IS_MAGIC'

dao_factory = factory(DAOMemoryFactory)
dao = DAOMemoryFactory.get_server()  # type: DAOMemoryServer

ksi_server = KSIServer(Identifier("server"), dao, filename_private_key="/tmp/private_key." + SIGN_KEY_FORMAT)

# The list of authorized users and their passwords (this ought to move to a DB in the future...)
user_dict = {'client': hash_factory(data=bytes('password', encoding="ascii") + SALT).digest()}


def callback_log(x: TimestampResponse):
    """
    The callback for the signature, it is actually not _needed_ but if we remove the callback argument to send_sign()
    then it is much harder to test. Thus, we use it as a logguer.
    """
    logging.info("Got callback with x: %s", x)


@auth.verify_password
def verify_password(username: str, password: str) -> str:
    res = False

    try:
        res = hash_factory(data=bytes(password, encoding="ascii") + SALT).digest() == user_dict[username]
    except KeyError:
        # User is not in user_dict
        pass

    return res


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


# curl -u client:password -H "Content-Type: application/json" -X POST -d '{"x":"YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwo=","ID_C":"client"}' http://localhost:5000/ksiapi/v0.1/sign
# {
#   "ID_C": "org.ksi.client",
#   "ID_S": "org.ksi.server",
#   "signature": "None",
#   "status_code": "CERTIFICATE_EXPIRED",
#   "t": "2016-02-10T15:27:44.746717",
#   "x": "YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwo="
# }
@app.route(API_ROUTE_BASE + 'sign', methods=['POST'])
@auth.login_required
def sign_request():
    """
    Sign a request, see API reference in the wiki.
    """
    if not request.json or 'x' not in request.json or 'ID_C' not in request.json:
        abort(400)

    return ksi_server.send_request(TimestampRequest.from_json(request.json), callback_log).to_json(), 201


@app.route(API_ROUTE_BASE + 'signed', methods=["GET"])
def get_signed_timestamps():
    """
    Return all the signed timestamps/requests, see API reference in the wiki.
    """
    res = {str(standard_b64encode(k), encoding="ascii"): str(v, encoding="ascii")
           for k, v in dao.get_signed_requests().items()}

    return jsonify({'signed_timestamps': res})


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    # We add something to the DAO
    client = KSIClient(ksi_server, dao_factory.get_client(), keys=Keys(l=8, seed=b'SEED'))
    client.sign(b'ABCD')

    # Launch the API
    app.run(debug=True)

    # Example of queries run against the API:
    #
    # curl -s -u client:password -H "Content-Type: application/json" -X POST -d \
    #   '{"x":"YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwo=","ID_C":"client"}' \
    #   http://localhost:5000/ksi/api/v0.1/sign \
    #   | python -m json.tool && \
    # echo -e "\n----------------" && \
    # curl -s -H "Content-Type: application/json" http://localhost:5000/ksi/api/v0.1/signed \
    #   | python -m json.tool && \
    # echo
    # {
    #     "t": "2016-02-11T12:52:26.756742",
    #     "status_code": "NO_ERROR",
    #     "ID_S": "org.ksi.server",
    #     "x": "YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwo=",
    #     "signature": "HHNT...Vz3mga/W+ZpelcnRi3A==",
    #     "ID_C": "org.ksi.client"
    # }
    #
    # ----------------
    # {
    #     "signed_timestamps": {
    #         "YWRjODNiMTllNzkzNDkxYjF...mU1OTJmYwp8b3JnLmtzaS5jbGllbnQ=": "HHNT...Vz3mga/W+ZpelcnRi3A==",
    #         "yp6EILHLPnl3BWOkkUyi7qPw4PNigF9mAENgsqHJ4uR8b3JnLmtzaS5jbGllbnQ=": "s6A/2tjlikxxFe...X4cqo/1w=="
    #     }
    # }
