from hashlib import md5
import json
import os

from flask import Flask
from flask import Response
from flask import request

app = Flask(__name__)

user_store = {
    'bugs@example.com': 'Password1'
    }

group_names = ['Everyone', 'StoreManager', 'Test1', 'Test2']

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


def make_okta_template(name):
    template = {
        "id": "Mocked-{}".format(name),
        "objectClass": ["okta:user_group"],
        "type": "OKTA_GROUP",
        "profile": {
            "name": name,
            "description": "Mocked Group {}".format(name)
        },
        "_links": {
            "logo": [
                {"name": "medium",
                 "href": "http://example.com/img.png",
                 "type": "image/png"},
                {"name": "large",
                 "href": "http://example.com/img.png",
                 "type": "image/png"}],
            "users": {
                # "https://example.com/api/v1/groups/456ABCD/users"
                "href": "http://example.com/mocked-not-implemented"
            },
            "apps": {
                # "https://example.com/api/v1/groups/456ABCD/users"
                "href": "http://example.com/mocked-not-implemented"
            }
        }
    }
    return template


def userid_from_username(username):
    return md5(username).hexdigest()


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/api/v1/users", methods=['POST'])
def users_create():
    data = request.get_json()
    username = data['profile']['email']
    password = data['credentials']['password']['value']
    userid = userid_from_username(username)

    success = {
        "id": userid,
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

    rv = make_okta_error("E0000001")
    status = 400

    if username not in user_store:
        user_store[username] = password
        rv = success
        rv['profile'] = data['profile']
        status = 200

    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/users/<username>")
def users_get(username):
    userid = userid_from_username(username)
    success = {
        "id": userid,
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
        rv = success
        status = 200
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/users/<id>/groups")
def users_groups(id):
    rv = []
    for group_name in ['Everyone', 'StoreManager', 'Test1', 'Test2']:
        group = make_okta_template(group_name)
        rv.append(group)
    status = 200
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/users/<id>/appLinks")
def users_applinks(id):
    object = [
        {
            "id": "0MockedAppLinksId",
            "label": "Mocked App Name",
            "linkUrl": "https://example.com/linkUrl",
            "logoUrl": "https://example.com/logoUrl",
            "appName": "mockedapp",
            "appInstanceId": "0MockedAppInstanceId",
            "appAssignmentId": "0MockedAppInstanceId",
            "credentialsSetup": False,
            "hidden": False,
            "sortOrder": 0
        }
    ]
    return Response(json.dumps(object),
                    mimetype='application/json')


@app.route("/api/v1/sessions", methods=["GET", "POST"])
def sessions():
    data = request.get_json()
    username = data['username']
    password = data['password']
    userid = userid_from_username(username)

    objectSuccess = {
        "id": "0MockedSessionId",
        "userId": userid,
        "mfaActive": False,
        "cookieToken": "MockedCookieToken"
    }

    rv = make_okta_error("E0000004")
    status = 401

    if username in user_store and user_store[username] == password:
        rv = objectSuccess
        status = 200

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
    success = {}

    rv = make_okta_error("E0000014")
    status = 403

    if new_password != "invalid":
        status = 200
        rv = success

    return Response(rv, status=status, mimetype='application/json')


@app.route("/api/v1/groups")
def groups():
    rv = []
    for group_name in group_names:
        group = make_okta_template(group_name)
        rv.append(group)
    status = 200
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')

if __name__ == "__main__":
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    if port == 5000:
        app.debug = True
    app.run(host='0.0.0.0', port=port)
