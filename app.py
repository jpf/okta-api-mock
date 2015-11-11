from hashlib import md5
import json
import os

from flask import Flask
from flask import Response
from flask import request
from flask import url_for

app = Flask(__name__)

users = {
    'Fox.Mulder@ic.fbi.example.com': {
        'password': 'trustno1',
        'profile': {
            'login': 'Fox.Mulder@ic.fbi.example.com',
            'email': 'Fox.Mulder@ic.fbi.example.com',
            'firstName': 'Fox',
            'lastName': 'Mulder',
            'locale': 'en_US',
            'timeZone': 'America/New_York',
            }
        },
    'bugs@example.com': {
        'password': 'WhatsUpD0c',
        'profile': {
            'login': 'bugs@example.com',
            'email': 'bugs@example.com',
            'firstName': 'Bugs',
            'lastName': 'Bunny',
            'locale': 'en_US',
            'timeZone': 'America/Los_Angeles',
            }
        },
    }


def validate_user(username, password):
    print("u: {}, p: {}".format(username, password))
    if username in users and users[username]['password'] == password:
        return users[username]
    else:
        print("... does not exist")
        return False

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
    "E0000011": {
        'short': "Invalid token provided"
        },
    "E0000014": {
        'short': "Update of credentials failed"
        },
    "E0000068": {
        'short': "Invalid Passcode/Answer",
        'long': "Your answer doesn't match our records. Please try again."
        },
    "E0000034": {
        'short': "Forgot password not allowed on specified user.",
        'long': "Recovery credential not set."
        }
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
    username_md5 = md5(username).hexdigest()
    uid = "mock_id_{}".format(username_md5)
    return uid


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/api/v1/users/", methods=['POST'])
def users_create_dir():
    return users_create()


@app.route("/api/v1/users", methods=['POST'])
def users_create():
    data = request.get_json()
    username = data['profile']['email']
    password = False
    if 'credentials' in data:
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

    if username not in users:
        users[username] = {}
        rv = success
        status = 200
        if password:
            users[username]['password'] = password
        if 'profile' in data:
            users[username]['profile'] = data['profile']
            rv['profile'] = data['profile']

    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/users/<username>")
def users_get(username):
    rv = make_okta_error("E0000007", extra=username)
    status = 404

    if username not in users:
        return Response(json.dumps(rv),
                        status=status,
                        mimetype='application/json')

    rv = {
        "id": userid_from_username(username),
        "status": "ACTIVE",
        "created": "2013-06-24T16:39:18.000Z",
        "activated": "2013-06-24T16:39:19.000Z",
        "statusChanged": "2013-06-24T16:39:19.000Z",
        "lastLogin": "2013-06-24T17:39:19.000Z",
        "lastUpdated": "2013-07-02T21:36:25.344Z",
        "passwordChanged": "2013-07-02T21:36:25.344Z",
        "profile": {
            "firstName": users[username]['profile']['firstName'],
            "lastName": users[username]['profile']['lastName'],
            "email": users[username]['profile']['login'],
            "login": users[username]['profile']['login'],
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


@app.route("/api/v1/users/<id>/factors/questions")
def users_factors_questions(id):
    rv = {}
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

    user = validate_user(username, password)
    if user:
        rv = objectSuccess
        status = 200

    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


def authn_MFA_UNENROLLED():
    return {
        "stateToken": "00Z20ZhXVrmyR3z8R-m77BvknHyckWCy5vNwEA6huD",
        "expiresAt": "2014-11-02T23:44:41.736Z",
        "status": "MFA_UNENROLLED",
        "relayState": "/myapp/some/deep/link/i/want/to/return/to",
        "_embedded": {
            "user": {
                "id": "00ub0oNGTSWTBKOLGLNR",
                "profile": {
                    "login": "isaac@example.org",
                    "firstName": "Isaac",
                    "lastName": "Brock",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            },
            "factors": [{
                "factorType": "question",
                "provider": "OKTA",
                "_links": {
                    "questions": {
                        "href": url_for('users_factors_questions',
                                        id='00uoy3CXZHSMMJPHYXXP',
                                        _external=True),
                        "hints": {"allow": ["GET"]}
                    },
                    "enroll": {
                        "href": url_for('authn_factors', _external=True),
                        "hints": {"allow": ["POST"]}
                    }
                }
            },
            {
                "factorType": "token:software:totp",
                "provider": "GOOGLE",
                "_links": {
                    "enroll": {
                        "href": url_for('authn_factors', _external=True),
                        "hints": {"allow": ["POST"]}
                    }
                }
            },
            {
                "factorType": "token:software:totp",
                "provider": "OKTA",
                "_links": {
                    "enroll": {
                        "href": url_for('authn_factors', _external=True),
                        "hints": {"allow": ["POST"]}
                    }
                }
            },
            ]
            },
        "_links": {
            "cancel": {
                "href": "https://your-domain.okta.com/api/v1/authn/cancel",
                "hints": {"allow": ["POST"]}
            }
        }
    }


# FIXME: Make sure this is a representative sample
def authn_MFA_ENROLL():
    return {
        "stateToken": "00Z20ZhXVrmyR3z8R-m77BvknHyckWCy5vNwEA6huD",
        "expiresAt": "2014-11-02T23:44:41.736Z",
        "status": "MFA_ENROLL",
        "relayState": "/myapp/some/deep/link/i/want/to/return/to",
        "_embedded": {
            "user": {
                "id": "00ub0oNGTSWTBKOLGLNR",
                "profile": {
                    "login": "isaac@example.org",
                    "firstName": "Isaac",
                    "lastName": "Brock",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            },
            "factors": [{
                "factorType": "question",
                "provider": "OKTA",
                "_links": {
                    "questions": {
                        "href": url_for('users_factors_questions',
                                        id='00uoy3CXZHSMMJPHYXXP',
                                        _external=True),
                        "hints": {"allow": ["GET"]}
                    },
                    "enroll": {
                        "href": url_for('authn_factors', _external=True),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }, {
                "factorType": "token:software:totp",
                "provider": "GOOGLE",
                "_links": {
                    "enroll": {
                        "href": url_for('authn_factors', _external=True),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }, {
                "factorType": "token:software:totp",
                "provider": "OKTA",
                "_links": {
                    "enroll": {
                        "href": url_for('authn_factors', _external=True),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }]
        },
        "_links": {
            "cancel": {
                "href": "https://your-domain.okta.com/api/v1/authn/cancel",
                "hints": {"allow": ["POST"]}
            }
        }
    }


def authn_PASSWORD_EXPIRED():
    return {
        "stateToken": "00s1pd3bZuOv-meJE13hz1B7SZl5EGc14Ii_CTBIYd",
        "expiresAt": "2014-11-02T23:39:03.319Z",
        "status": "PASSWORD_EXPIRED",
        "relayState": "/myapp/some/deep/link/i/want/to/return/to",
        "_embedded": {
            "user": {
                "id": "00ub0oNGTSWTBKOLGLNR",
                "profile": {
                    "login": "isaac@example.org",
                    "firstName": "Isaac",
                    "lastName": "Brock",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            }
        },
        "_links": {
            "next": {
                "name": "password",
                "href": url_for('authn_change_password', _external=True),
                "hints": {
                    "allow": ["POST"]
                }
            },
            "cancel": {
                "href": url_for('authn_cancel', _external=True),
                "hints": {
                    "allow": ["POST"]
                }
            }
        }
    }


def authn_MFA_REQUIRED():
    return {
        "stateToken": "00FpGOgqHfl-6KZxh1bLXJDz35ENsShIY-lc5XHPzc",
        "expiresAt": "2014-11-02T23:35:28.269Z",
        "status": "MFA_REQUIRED",
        "relayState": "/myapp/some/deep/link/i/want/to/return/to",
        "_embedded": {
            "user": {
                "id": "00ub0oNGTSWTBKOLGLNR",
                "profile": {
                    "login": "isaac@example.org",
                    "firstName": "Isaac",
                    "lastName": "Brock",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            },
            "factors": [{
                "id": "ufsm3jZGDQXPJDEIXZMP",
                "factorType": "question",
                "provider": "OKTA",
                "profile": {
                    "question": "disliked_food",
                    "questionText": "What is the food you least like?"
                },
                "_links": {
                    "verify": {
                        "href": url_for('authn_factor_verify',
                                        _external=True,
                                        factor_id='ufsm3jZGDQXPJDEIXZMP'),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }, {
                "id": "rsalhpMQVYKHZKXZJQEW",
                "factorType": "token",
                "provider": "RSA",
                "profile": {
                    "credentialId": "isaac@example.org"
                },
                "_links": {
                    "verify": {
                        "href": url_for('authn_factor_verify',
                                        _external=True,
                                        factor_id='rsalhpMQVYKHZKXZJQEW'),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }, {
                "id": "uftm3iHSGFQXHCUSDAND",
                "factorType": "token:software:totp",
                "provider": "GOOGLE",
                "profile": {
                    "credentialId": "isaac@example.org"
                },
                "_links": {
                    "verify": {
                        "href": url_for('authn_factor_verify',
                                        _external=True,
                                        factor_id='uftm3iHSGFQXHCUSDAND'),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }, {
                "id": "ostfm3hPNYSOIOIVTQWY",
                "factorType": "token:software:totp",
                "provider": "OKTA",
                "profile": {
                    "credentialId": "isaac@example.org"
                },
                "_links": {
                    "verify": {
                        "href": url_for('authn_factor_verify',
                                        _external=True,
                                        factor_id='ostfm3hPNYSOIOIVTQWY'),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }, {
                "id": "sms193zUBEROPBNZKPPE",
                "factorType": "sms",
                "provider": "OKTA",
                "profile": {
                    "phoneNumber": "+1 XXX-XXX-1337"
                },
                "_links": {
                    "verify": {
                        "href": url_for('authn_factor_verify',
                                        _external=True,
                                        factor_id='sms193zUBEROPBNZKPPE'),
                        "hints": {"allow": ["POST"]}
                    }
                }
            }]
        },
        "_links": {
            "cancel": {
                "href": url_for('authn_cancel', _external=True),
                "hints": {"allow": ["POST"]}
            }
        }
    }


def authn_RECOVERY_PASSWORD():
    return {
        "expiresAt": "3015-06-10T18:29:32.000Z",
        "status": "RECOVERY",
        # FIXME: This should eventually be something dynamic,
        #        to prevent testers from hard coding tokens.
        #        Probably should come from  "create_recovery_token()"
        "recoveryToken": "MockedRecoveryToken",
        "_embedded": {
            "user": {
                "id": "00u2wv6awzNNEBGLANDG",
                "profile": {
                    "login": "user_CAN_RECOVER_PASSWORD@example.com",
                    "firstName": "User",
                    "lastName": "Canrecoverpassword",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            }
        },
        "_links": {
            "next": {
                "name": "recovery",
                "href": url_for('authn_recovery_token',
                                _external=True),
                "hints": {
                    "allow": [
                        "POST"
                    ]
                }
            },
            "cancel": {
                "href": url_for('authn_cancel',
                                _external=True),
                "hints": {
                    "allow": [
                        "POST"
                    ]
                }
            }
        }
    }


def authn_RECOVERY_TOKEN():
    return {
        "stateToken": "MockedStateToken",
        "expiresAt": "3015-06-03T18:35:57.269Z",
        "status": "RECOVERY",
        "_embedded": {
            "user": {
                "id": "00u2wv6awzNNEBGLANDG",
                "profile": {
                    "login": "user_CAN_RECOVER_PASSWORD@example.com",
                    "firstName": "User",
                    "lastName": "Canrecoverpassword",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                },
                "recovery_question": {
                    "question": "What is the food you least liked as a child?"
                }
            }
        },
        "_links": {
            "next": {
                "name": "answer",
                "href": url_for('authn_recovery_answer',
                                _external=True),
                "hints": {
                    "allow": [
                        "POST"
                    ]
                }
            },
            "cancel": {
                "href": url_for('authn_cancel',
                                _external=True),
                "hints": {
                    "allow": [
                        "POST"
                    ]
                }
            }
        }
    }


def authn_RECOVERY_ANSWER():
    return {
        "stateToken": "MockedStateToken",
        "expiresAt": "3015-06-03T18:39:26.064Z",
        "status": "PASSWORD_RESET",
        "_embedded": {
            "user": {
                "id": "00u2wv6awzNNEBGLANDG",
                "profile": {
                    "login": "user_CAN_RECOVER_PASSWORD@example.com",
                    "firstName": "User",
                    "lastName": "Canrecoverpassword",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            }
        },
        "_links": {
            "next": {
                "name": "resetPassword",
                "href": url_for('authn_credentials_reset_password',
                                _external=True),
                "hints": {
                    "allow": [
                        "POST"
                    ]
                }
            },
            "cancel": {
                "href": url_for('authn_cancel',
                                _external=True),
                "hints": {
                    "allow": [
                        "POST"
                    ]
                }
            }
        }
    }


def object_success():
    return {
        "expiresAt": "3014-11-03T10:15:57.100Z",
        "status": "SUCCESS",
        "relayState": "/mocked/relayState",
        "sessionToken": "MockedSessionToken",
        "_embedded": {
            "user": {
                "id": "00u2wv6awzNNEBGLANDG",
                "profile": {
                    "login": "user_CAN_RECOVER_PASSWORD@example.org",
                    "firstName": "User",
                    "lastName": "Canrecoverpassword",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            }
        }
    }


@app.route("/api/v1/authn/recovery/password", methods=["POST"])
def authn_recovery_password():
    data = request.get_json()
    username = data['username']

    rv = make_okta_error('E0000034')
    status = 403

    if username == 'user_CAN_RECOVER_PASSWORD@example.com':
        rv = authn_RECOVERY_PASSWORD()
        status = 200
    elif username == 'user_CANT_RECOVER_PASSWORD@example.com':
        pass
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/authn/recovery/token", methods=["POST"])
def authn_recovery_token():
    data = request.get_json()
    recovery_token = data['recoveryToken']

    rv = make_okta_error("E0000011")
    status = 401

    # FIXME: This should be validated by a function, say
    #        "validate_recovery_token()"
    if recovery_token == 'MockedRecoveryToken':
        rv = authn_RECOVERY_TOKEN()
        status = 200
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/authn/recovery/answer", methods=["POST"])
def authn_recovery_answer():
    data = request.get_json()
    state_token = data['stateToken']
    answer = data['answer']

    # FIXME: Make sure this is the correct error
    rv = make_okta_error("E0000011")
    status = 401

    # FIXME: This should be validated by a function, say
    #        "validate_recovery_token()"
    if state_token != 'MockedRecoveryToken':
        pass
    if answer != 'Candy':
        rv = make_okta_error("")
        status = 401
    else:
        rv = authn_RECOVERY_ANSWER()
        status = 200
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/authn/credentials/reset_password", methods=["POST"])
def authn_credentials_reset_password():
    data = request.get_json()
    state_token = data['stateToken']
    new_password = data['newPassword']

    # FIXME: Make sure this is the correct error
    rv = make_okta_error("E0000011")
    status = 401

    # FIXME: This should be validated by a function, say
    #        "validate_recovery_token()"
    if state_token != 'MockedRecoveryToken':
        pass
    # FIXME: Add this feature
    # if !valid(new_password):
    #     rv = make_okta_error("")
    #     status = 401
    else:
        rv = object_success()
        status = 200
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/authn/factors", methods=["POST"])
def authn_factors():
    pass


@app.route("/api/v1/authn/factors/<factor_id>/verify", methods=["POST"])
def authn_factor_verify(factor_id):
    data = request.get_json()
    objectSuccess = {
        "expiresAt": "2014-11-03T10:15:57.100Z",
        "status": "SUCCESS",
        "relayState": "/mocked/relayState",
        "sessionToken": "MockedSessionToken",
        "_embedded": {
            "user": {
                "id": "00ub0oNGTSWTBKOLGLNR",
                "profile": {
                    "login": "isaac@example.org",
                    "firstName": "Isaac",
                    "lastName": "Brock",
                    "locale": "en_US",
                    "timeZone": "America/Los_Angeles"
                }
            }
        }
    }
    rv = make_okta_error("E0000068")
    status = 401

    if factor_id == 'ostfm3hPNYSOIOIVTQWY' and data['passCode'] == '123456':
        rv = objectSuccess
        status = 200
    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


@app.route("/api/v1/authn/credentials/change_password", methods=["POST"])
def authn_change_password():
    pass


@app.route("/api/v1/authn/cancel", methods=["POST"])
def authn_cancel():
    pass


# @app.route("/api/v1/authn/", methods=["POST"])
# def authn_slash():
#     return authn()


@app.route("/api/v1/authn", methods=["GET", "POST"])
def authn():
    data = request.get_json()
    username = data['username']
    password = data['password']
    userid = userid_from_username(username)

    objectSuccess = {
        "expiresAt": "2014-11-03T10:15:57.000Z",
        "status": "SUCCESS",
        "relayState": "/mocked/relayState",
        "sessionToken": "MockedSessionToken",
        "_embedded": {
            "user": {
                }
            }
        }

    rv = make_okta_error("E0000004")
    status = 401

    user = validate_user(username, password)
    if user:
        rv = objectSuccess
        rv['_embedded']['id'] = userid
        rv['_embedded']['profile'] = user['profile']
        status = 200
    elif username == 'user_no_embedded_profile@example.com':
        rv = objectSuccess
        rv['user'] = {
            'profile': user['profile']
            }
        status = 200
    elif username == 'user_PASSWORD_EXPIRED@example.com':
        print("Got {}".format(username))
        rv = authn_PASSWORD_EXPIRED()
        status = 200
    elif username == 'user_MFA_REQUIRED@example.com':
        print("Got {}".format(username))
        rv = authn_MFA_REQUIRED()
        status = 200
    elif username == 'user_MFA_UNENROLLED@example.com':
        print("Got {}".format(username))
        rv = authn_MFA_UNENROLLED()
        status = 200
    elif username == 'user_MFA_ENROLL@example.com':
        print("Got {}".format(username))
        rv = authn_MFA_ENROLL()
        status = 200

    return Response(json.dumps(rv),
                    status=status,
                    mimetype='application/json')


# {{url}}/api/v1/users/00u2wv6awzNNEBGLANDG/lifecycle/reset_password?sendEmail=false
    # {
    #     "resetPasswordUrl": "https://jfranusic.oktapreview.com/reset_password/1IBEyUADkyh40WRZn2-C"
    # }

# {{url}}/api/v1/users?q=john.doe@example.com
    # [
    #     {
    #         "id": "00u2wv6awzNNEBGLANDG",
    #         "status": "ACTIVE",
    #         "created": "2014-11-06T22:11:45.000Z",
    #         "activated": "2014-11-06T22:11:49.000Z",
    #         "statusChanged": "2014-11-06T22:11:49.000Z",
    #         "lastLogin": "2015-06-03T18:36:26.000Z",
    #         "lastUpdated": "2015-06-03T18:36:26.000Z",
    #         "passwordChanged": "2015-06-03T18:36:26.000Z",
    #         "profile": {
    #             "email": "john.doe@example.com",
    #             "firstName": "John",
    #             "lastName": "Doe",
    #             "login": "john.doe@example.com",
    #             "mobilePhone": "415-555-1212",
    #             "secondEmail": null
    #         },
    #         "credentials": {
    #             "password": {},
    #             "recovery_question": {
    #                 "question": "What is the food you least liked as a child?"
    #             },
    #             "provider": {
    #                 "type": "OKTA",
    #                 "name": "OKTA"
    #             }
    #         },
    #         "_links": {
    #             "resetPassword": {
    #                 "href": "https://jfranusic.oktapreview.com/api/v1/users/00u2wv6awzNNEBGLANDG/lifecycle/reset_password",
    #                 "method": "POST"
    #             },
    #             "expirePassword": {
    #                 "href": "https://jfranusic.oktapreview.com/api/v1/users/00u2wv6awzNNEBGLANDG/lifecycle/expire_password",
    #                 "method": "POST"
    #             },
    #             "forgotPassword": {
    #                 "href": "https://jfranusic.oktapreview.com/api/v1/users/00u2wv6awzNNEBGLANDG/credentials/forgot_password",
    #                 "method": "POST"
    #             },
    #             "changeRecoveryQuestion": {
    #                 "href": "https://jfranusic.oktapreview.com/api/v1/users/00u2wv6awzNNEBGLANDG/credentials/change_recovery_question",
    #                 "method": "POST"
    #             },
    #             "deactivate": {
    #                 "href": "https://jfranusic.oktapreview.com/api/v1/users/00u2wv6awzNNEBGLANDG/lifecycle/deactivate",
    #                 "method": "POST"
    #             },
    #             "changePassword": {
    #                 "href": "https://jfranusic.oktapreview.com/api/v1/users/00u2wv6awzNNEBGLANDG/credentials/change_password",
    #                 "method": "POST"
    #             }
    #         }
    #     }
    # ]

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
    app.run(port=port)
