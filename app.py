from flask import Flask
from flask import request
from flask import Response
from hashlib import md5
import json
app = Flask(__name__)

prefix = '/api/vi'

user_store = {
    'bugs@example.com': 'Password1'
    }

data = {
    'data': 0
    }

errors = {
    "E0000001": {
        "short": "Api validation failed: login",
        "long": ("login: An object with this field "
                 "already exists in the current organization")
        },
    "E0000004": {
        "short": "Authentication failed",
        },
    "E0000007": {
        "short": "Not found: Resource not found: {} (User)"
        },
    "E0000014": {
        'short': "Update of credentials failed"
        },
    }


def make_okta_error(errorCode, extra=False):
    template = {
        'errorLink': errorCode,
        'errorCode': errorCode,
        'errorId': 'MockedErrorId',
        'errorSummary': '',
        'errorCauses': [],
        }
    error = errors[errorCode]
    if 'short' in error:
        template['errorSummary'] = error['short']
    if 'long' in error:
        template['errorCauses'] = [{'errorSummary': error['long']}]

    if errorCode == "E0000007" and extra:
        template['errorSummary'] = error['short'].format(extra)
    return template


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/add")
def add():
    data["data"] += 1
    return "Value: {}".format(data['data'])


@app.route("/view")
def view():
    return "Value: {}".format(data['data'])


@app.route("/api/v1/users", methods=['POST'])
def users_create():
    data = request.get_json()
    print data
    username = data['profile']['email']
    password = data['credentials']['password']['value']

    rvFailure = make_okta_error("E0000001")

    rvSuccess = {
        "id": "00u2vgou9lPHZELCZKKO",
        "status": "STAGED",
        "transitioningToStatus": "ACTIVE",
        "created": "2014-10-29T17:02:03.000Z",
        "activated": None,
        "statusChanged": None,
        "lastLogin": None,
        "lastUpdated": "2014-10-29T17:02:03.000Z",
        "passwordChanged": "2014-10-29T17:02:03.000Z",
        "profile": {},
        "credentials": {
            "password": {},
            "provider": {
                "type": "OKTA",
                "name": "OKTA"
                }
            },
        "_links": {}
        }

    rv = rvFailure
    status = 400

    if username not in user_store:
        user_store[username] = password
        rv = rvSuccess
        rv['profile'] = data['profile']
        status = 200

    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/users/<username>")
def users_get(username):
    id = md5(username).hexdigest()
    rvSuccess = {
        "id": id,
        "status": "ACTIVE",
        "created": "2013-06-24T16:39:18.000Z",
        "activated": "2013-06-24T16:39:19.000Z",
        "statusChanged": "2013-06-24T16:39:19.000Z",
        "lastLogin": "2013-06-24T17:39:19.000Z",
        "lastUpdated": "2013-07-02T21:36:25.344Z",
        "passwordChanged": "2013-07-02T21:36:25.344Z",
        "profile": {
            "firstName": "FAKE",
            "lastName": "FAKE",
            "email": username,
            "login": username,
            "mobilePhone": "415-555-1212"
        },
        "credentials": {
            "password": {},
            "recovery_question": {
                "question": "What is your name?"
            },
            "provider": {
                "type": "OKTA",
                "name": "OKTA"
            }
        }
    }

    rv = make_okta_error("E0000007", extra=username)
    status = 404

    if username in user_store:
        rv = rvSuccess
        status = 200
    return Response(json.dumps(rv), status=status, mimetype='application/json')


@app.route("/api/v1/users/<id>/appLinks")
def users_applinks(id):
    object = [
        {
            "id": "00ub0oNGTSWTBKOLGLNR",
            "label": "Google Apps Mail",
            "linkUrl": "https://example.com/linkUrl",
            "logoUrl": "https://example.com/logoUrl",
            "appName": "google",
            "appInstanceId": "0oa3omz2i9XRNSRIHBZO",
            "appAssignmentId": "0ua3omz7weMMMQJERBKY",
            "credentialsSetup": False,
            "hidden": False,
            "sortOrder": 0
        }
    ]
    return Response(json.dumps(object),  mimetype='application/json')


@app.route("/api/v1/sessions", methods=["GET", "POST"])
def sessions():
    data = request.get_json()
    username = data['username']
    password = data['password']

    objectSuccess = {
        "id": "000kYk6cDF7R02z4PxV5mhL4g",
        "userId": "00u9apFCRAIKHVPZLGXT",
        "mfaActive": False,
        "cookieToken": "MockedCookieToken"
    }

    rv = make_okta_error("E0000004")
    status = 401
    if username in user_store and user_store[username] == password:
        rv = objectSuccess
        status = 200
    print "Data: {}, Status: {}".format(data, status)
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/users/<user_id>/lifecycle/deactivate", methods=['POST'])
def users_lifecycle_deactivate(user_id):
    return Response('{}', mimetype='application/json')


@app.route("/api/v1/users/<user_id>/credentials/change_password",
           methods=['POST'])
def users_credentials_change_password(user_id):
    data = request.get_json()

    # FIXME: Check if the oldPassword is valid
    new_password = data['newPassword']['value']

    # FIXME: This is different from here!
    # http://developer.okta.com/docs/api/rest/users.html#change-password
    rvSuccess = {}

    rv = make_okta_error("E0000014")
    status = 403

    print "New password: {}".format(new_password)

    if new_password != "invalid":
        status = 200
        rv = rvSuccess

    return Response(rv, status=status, mimetype='application/json')


if __name__ == "__main__":
    app.debug = True
    app.run("0.0.0.0")
    # app.run()
