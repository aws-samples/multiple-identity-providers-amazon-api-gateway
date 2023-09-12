import os
import json
import sys
import time
import urllib.request

envLambdaTaskRoot = os.environ["LAMBDA_TASK_ROOT"]
sys.path.insert(0,os.environ["LAMBDA_TASK_ROOT"]+"/dependencies")

import boto3
from jose import jwk, jwt
from jose.utils import base64url_decode

# envs
AWS_REGION = os.environ['AWS_REGION']
COGNITO_INTERNAL_USER_POOL_ID = os.environ['COGNITO_INTERNAL_USER_POOL_ID']
COGNITO_INTERNAL_APP_CLIENT_ID = os.environ['COGNITO_INTERNAL_APP_CLIENT_ID']
COGNITO_EXTERNAL_USER_POOL_ID = os.environ['COGNITO_EXTERNAL_USER_POOL_ID']
COGNITO_EXTERNAL_APP_CLIENT_ID = os.environ['COGNITO_EXTERNAL_APP_CLIENT_ID']
VERIFIED_PERMISSION_POLICY_STORE_ID = os.environ['VERIFIED_PERMISSION_POLICY_STORE_ID']

keys_url1 = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(AWS_REGION, COGNITO_INTERNAL_USER_POOL_ID)
keys_url2 = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(AWS_REGION, COGNITO_EXTERNAL_USER_POOL_ID)
# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/

# Excluding [B310] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected. 
# URLs are verified above
keys = {}
with urllib.request.urlopen(keys_url1) as f: # nosec B310
    response = f.read()
keys['internal'] = json.loads(response.decode('utf-8'))['keys']
with urllib.request.urlopen(keys_url2) as f: # nosec B310
    response = f.read()
keys['external'] = json.loads(response.decode('utf-8'))['keys']


def handler(event, context):
    print('Event: ', event)

    token_data = parse_token_data(event)
    client_type_data = parse_client_type(event)
    
    if token_data['valid'] is False or client_type_data['valid'] is False:
        return get_deny_policy()

    try:
        client_keys = keys.get(client_type_data['client_type'])
        claims = verify_token(token_data['token'], client_keys)
        
        role = claims['custom:Role']
        username = claims['cognito:username']
        method_arn = event['methodArn']
        return is_authorized(role, username, method_arn)

    except Exception as e:
        print(e)

    return get_deny_policy()

def is_authorized(role: str, username:str, method_arn):
    authorization_service = boto3.client('verifiedpermissions')
    """authorization decision
      1. build authorization query
      2. call isAuthorized and get decision
      3. based on decision, return an explicit allow or deny policy
    """
    items = method_arn.rsplit("/")
    print('items ', items)
    
    action = "{}/{}".format(items[2], items[3])
    if len(items) > 4:
        appointmentId = items[4]
    else: 
      print('Appointment id is missing in URI')
      return get_deny_policy()
    
    authorizationQuery = {
       "policyStoreId": VERIFIED_PERMISSION_POLICY_STORE_ID,
       "principal":{
          "entityType": "username",
          "entityId": username
       },
       "action":{
          "actionType":"Action",
          "actionId": action
       },
       "resource": {
          "entityType": "appointmentId",
          "entityId": items[4]
       },
       "entities": get_entities()
    }
    # print('authorizationQuery: ', authorizationQuery)
    authZResult = authorization_service.is_authorized( **authorizationQuery )
    print("Authorization Decision:" + authZResult.get("decision"))

    policy = {
        'Version': "2012-10-17",
        'Statement': {}
    }
    if authZResult.get("decision") == "ALLOW":
        policy['Statement']['Action'] = 'execute-api:Invoke'
        policy['Statement']['Effect'] = authZResult.get("decision")
        policy['Statement']['Resource'] = method_arn
        return get_response_object(policy)
    return get_deny_policy()
        
    
"""----------------build entities structure---------------------"""
def get_entities():
  entities = {
    "entityList": [
    {
      "identifier": {
        "entityType": "username",
        "entityId": "Dave"
      },
      "parents": [
        {
          "entityType": "UserGroup",
          "entityId": "AllClients"
        }
      ]
    },
    {
      "identifier": {
        "entityType": "username",
        "entityId": "Joy"
      },
      "parents": [
        {
          "entityType": "UserGroup",
          "entityId": "AllClients"
        }
      ]
    },
    {
      "identifier": {
        "entityType": "UserGroup",
        "entityId": "AllClients"
      }
    },
    {
      "identifier": {
        "entityType": "username",
        "entityId": "Adam"
      },
      "parents": [
        {
          "entityType": "UserGroup",
          "entityId": "AllVeterinarians"
        }
      ]
    },
    {
      "identifier": {
        "entityType": "username",
        "entityId": "Jane"
      },
      "parents": [
        {
          "entityType": "UserGroup",
          "entityId": "AllVeterinarians"
        }
      ]
    },
    {
      "identifier": {
        "entityType": "UserGroup",
        "entityId": "AllClients"
      }
    },
    {
      "identifier": {
        "entityType": "UserGroup",
        "entityId": "AllVeterinarians"
      }
    },
    {
      "identifier": {
        "entityType": "appointmentId",
        "entityId": "PI-T123"
      },
      "parents": [
        {
          "entityType": "UserGroup",
          "entityId": "AllClients"
        },
        {
          "entityType": "UserGroup",
          "entityId": "AllVeterinarians"
        }
      ],
      "attributes": {
        "owner": {
          "entityIdentifier": {
            "entityType": "username",
            "entityId": "Dave"
          }
        },
        "Veterinarian": {
          "entityIdentifier": {
            "entityType": "username",
            "entityId": "Jane"
          }
        }
      }
    },
    {
      "identifier": {
        "entityType": "appointmentId",
        "entityId": "PI-T124"
      },
      "parents": [
        {
          "entityType": "UserGroup",
          "entityId": "AllClients"
        },
        {
          "entityType": "UserGroup",
          "entityId": "AllVeterinarians"
        }
      ],
      "attributes": {
        "owner": {
          "entityIdentifier": {
            "entityType": "username",
            "entityId": "Joy"
          }
        },
        "Veterinarian": {
          "entityIdentifier": {
            "entityType": "username",
            "entityId": "Jane"
          }
        }
      }
    },
    {
      "identifier": {
        "entityType": "appointmentId",
        "entityId": "PI-T125"
      },
      "parents": [
        {
          "entityType": "UserGroup",
          "entityId": "AllClients"
        },
        {
          "entityType": "UserGroup",
          "entityId": "AllVeterinarians"
        }
      ],
      "attributes": {
        "owner": {
          "entityIdentifier": {
            "entityType": "username",
            "entityId": "Dave"
          }
        },
        "Veterinarian": {
          "entityIdentifier": {
            "entityType": "username",
            "entityId": "Adam"
          }
        }
      }
    }
  ]                
  }

  return entities

    
def get_response_object(policyDocument, principalId='yyyyyyyy', context={}):
    response =  {
        "principalId": principalId,
        "policyDocument": policyDocument,
        "context": context,
        "usageIdentifierKey": "{api-key}"
    }
    print('response: ', response)
    return response


def get_deny_policy():
    return {
        "principalId": "yyyyyyyy",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": "arn:aws:execute-api:*:*:*/ANY/*"
                }
            ]
        },
        "context": {},
        "usageIdentifierKey": "{api-key}"
    }

def parse_client_type(event):
    response = {'valid': False}

    if 'clienttype' not in event['headers']:
        print('ClientType not present')
        return response

    client_type = event['headers']['clienttype']
    print('client_type' , client_type)

    # deny request of header isn't made out of two strings, or
    # first string isn't equal to "Bearer" (enforcing following standards,
    # but technically could be anything or could be left out completely)
    if not keys.get(client_type):
        return response

    print('client_type: ', client_type)
    return {
        'valid': True,
        'client_type': client_type
    }


def parse_token_data(event):
    response = {'valid': False}

    if 'Authorization' not in event['headers']:
        print('Authorization not present')
        return response

    auth_header = event['headers']['Authorization']
    print('auth_header' , auth_header)
    auth_header_list = auth_header.split(' ')

    # deny request of header isn't made out of two strings, or
    # first string isn't equal to "Bearer" (enforcing following standards,
    # but technically could be anything or could be left out completely)
    if len(auth_header_list) != 2 or auth_header_list[0] != 'Bearer':
        return response

    access_token = auth_header_list[1]
    print('access_token: ', access_token)
    return {
        'valid': True,
        'token': access_token
    }


def verify_token(token, client_keys):
    # get the kid from the headers prior to verification
    print('token', token)
    headers = jwt.get_unverified_headers(token)
    print('headers: ', headers)
    print('client_keys: ', client_keys)
    kid = headers['kid']
    
    print('kid: ', kid)

    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(client_keys)):
        if kid == client_keys[i]['kid']:
            key_index = i
            break

    
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False

    # construct the public key
    public_key = jwk.construct(client_keys[key_index])

    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)

    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False

    print('Signature successfully verified')

    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)

    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False

    # now we can use the claims
    print('claims: ', claims)
    return claims