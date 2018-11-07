import re
import sys
import json
import requests

CLIENT_ID = 'client-asdf12-34as-df12-34as-df1234asdf12'
CLIENT_PASSWORD = 'asdf1234asdf1234asdf1234asdf1234asdf1234asdf1234asdf12'

def generate_token():
    ''' Generate a new access token and write it to disk
    '''
    url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'

    headers = {'Content-Type':'application/x-www-form-urlencoded',
               'Accept':'application/json'}

    payload = {'grant_type':'client_credentials'}

    response = requests.post(url, headers=headers, auth=(CLIENT_ID, CLIENT_PASSWORD), data=payload)

    if need_new_token(response):
        sys.exit('Unable to generate new token!\nCheck your CLIENT_ID and CLIENT_PASSWORD')

    response_json = response.json()
    access_token = response_json['access_token']

    with open('threat_response_token', 'w') as token_file:
        token_file.write(access_token)

def post(sha256):
    ''' Query the API for a SHA256
    '''
    enrich_url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/deliberate/observables'

    for i in range(2):
        while True:
            try:
                with open('threat_response_token', 'r') as token_file:
                    access_token = token_file.read()
            except FileNotFoundError:
                print('threat_response_token file not found, generating new token.')
                generate_token()
            break

    headers = {'Authorization':'Bearer {}'.format(access_token),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    observables_payload = [{'value': sha256, 'type': 'sha256'}]
    observables_payload = json.dumps(observables_payload)

    response = requests.post(enrich_url, headers=headers, data=observables_payload)

    return response

def need_new_token(response):
    ''' Check the status code of the response
    '''
    if response.status_code == 401:
        return True
    return False

def query(sha256):
    ''' Query the API and validate authentication was successful
        If authentication fails, generate a new token and try again
    '''
    response = post(sha256)
    if need_new_token(response):
        print('Auth failed, generating new token.')
        generate_token()
        response = post(sha256)
    return response

def ask_for_sha256():
    '''Ask for SHA256
    '''
    while True:
        reply = str(input('Enter a SHA256: ')).strip()
        if validate_sha256(reply):
            return reply
        if not validate_sha256(reply):
            print('Not a valid SHA256')

def validate_sha256(sha256):
    ''' Validate the SHA256
    '''
    match_obj = re.match(r"[a-fA-F0-9]{64}$", sha256)
    return bool(match_obj)

def main():
    ''' Main script logic
    '''
    try:
        sha256 = sys.argv[1]
        if not validate_sha256(sha256):
            print('{} is not a valid SHA256'.format(sha256))
            sha256 = ask_for_sha256()
    except IndexError:
        sha256 = ask_for_sha256()

    response = query(sha256)
    response_json = response.json()

    for module in response_json['data']:
        module_name = module['module']
        if module_name == 'AMP File Reputation':
            if  module['data']['verdicts']['count'] > 0:
                docs = module['data']['verdicts']['docs']
                for doc in docs:
                    disposition = doc['disposition']
                    disposition_name = doc['disposition_name']
            else:
                disposition = 0
                disposition_name = 'Unknown/Unseen'

    print('{} {} {}'.format(disposition, disposition_name, sha256))

if __name__ == '__main__':
    main()
