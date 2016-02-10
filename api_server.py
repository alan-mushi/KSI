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
from ksi import API_ROUTE_BASE

#
# REST API.
# This file is executable as a "standalone" script.
#

app = Flask(__name__)
auth = HTTPBasicAuth()

dao_factory = factory(DAOMemoryFactory)
dao = DAOMemoryFactory.get_server()  # type: DAOMemoryServer

ksi_server = KSIServer(Identifier("server"), dao, filename_private_key="/tmp/private_key." + SIGN_KEY_FORMAT)

# The list of authorized users and their passwords (this ought to move to a DB in the future...)
user_dict = {'client': 'password'}


def callback_log(x: TimestampResponse):
    """
    The callback for the signature, it is actually not _needed_ but if we remove the callback argument to send_sign()
    then it is much harder to test. Thus, we use it as a logguer.
    """
    logging.info("Got callback with x: %s", x)


@auth.get_password
def get_password(username: str) -> str:
    password = None
    try:
        password = user_dict[username]
    except KeyError:
        # User is not in user_dict
        pass

    return password


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
#  "x": "YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwo="
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
    # curl -u client:password -H "Content-Type: application/json" -X POST -d '{"x":"YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwo=","ID_C":"client"}' http://localhost:5000/ksi/api/v0.1/sign && echo -e "\n----------------" && curl -H "Content-Type: application/json" http://localhost:5000/ksi/api/v0.1/signed && echo
    # {
    # 	"ID_C": "org.ksi.client",
    # 		"ID_S": "org.ksi.server",
    # 		"signature": "None",
    # 		"status_code": "CERTIFICATE_EXPIRED",
    # 		"t": "2016-02-10T15:58:35.399558",
    # 		"x": "YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwo="
    # }
    # ----------------
    # {
    # 	"signed_timestamps": {
    # 		"YWRjODNiMTllNzkzNDkxYjFjNmVhMGZkOGI0NmNkOWYzMmU1OTJmYwpvcmcua3NpLmNsaWVudA==": "p7MwqNKWkPfh57XEOimMJ2cWAagvFigxzvBeNKf9yZi8uITIha7eMl+qvfmi7QSgFI/xV9+xeaPKQiV/H4L0XkUgI6rNj+GNXf/394wxkRj6JjihoxL+EMnBD7A4w8r/b8q6CysVdl3Y79CYR0t8CtG5byGdkSVWd0d7U8BniSrbmzMJiPUHWtiuytQOJK1LfAkLm+fW7XZBBUqggzgnvXKY4U0aPHnbX37cuFvGNKUlQCA39GMGWZOd6ERVTOGoZi0adZIwdOv25+se8tZ89mPgwj5w+pT/fDn2T4shytPOZ5OzvYsejEa1OcYbl+pMlFS+PJEvriDQobsdjsVAmA==",
    # 		"yp6EILHLPnl3BWOkkUyi7qPw4PNigF9mAENgsqHJ4uRvcmcua3NpLmNsaWVudA==": "PsJTYEVcaSP3Zx18ipYJRfQ3Q3atg0IB5aDK9VkLc917BirUC7g/YUJngdNzGZnNXQeCjQldbWiynB6Yosw0Ewp9S+eG0CCuVsydKoa8GuAv6k/JJxzquXjpcCFwThbZZ2GMT29WHsHDZ9MsBBkUcfYMQ2KfrRJoYf1lrrGmMrnjsvQdqZgx6sipiVBGpleTPxuzeR84Wtghju+sea5JFjsfh60zRC693VwxfdauUw84CRBoqLYvZ1SFT1LatwxDMzkKDhJHyXYGVAj4X5OejRxcAGiHheZXsUlppDzHrAq22wzLChD1sS/FnaBu/4Y1EmlCq3bsWIbn6nliXVbX/Q=="
    # 	}
    # }
