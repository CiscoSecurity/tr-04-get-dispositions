import sys
import json
import requests

CLIENT_ID = 'client-asdf12-34as-df12-34as-df1234asdf12'
CLIENT_PASSWORD = 'asdf1234asdf1234asdf1234asdf1234asdf1234asdf1234asdf12'

SESSION = requests.session()

def generate_token():
    ''' Generate a new access token and write it to disk
    '''
    url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'

    headers = {'Content-Type':'application/x-www-form-urlencoded',
               'Accept':'application/json'}

    payload = {'grant_type':'client_credentials'}

    response = requests.post(url, headers=headers, auth=(CLIENT_ID, CLIENT_PASSWORD), data=payload)

    if unauthorized(response):
        sys.exit('Unable to generate new token!\nCheck your CLIENT_ID and CLIENT_PASSWORD')

    response_json = response.json()
    access_token = response_json['access_token']

    with open('threat_response_token', 'w') as token_file:
        token_file.write(access_token)

def get_token():
    ''' Get the access token from disk if it's not there generate a new one
    '''
    for i in range(2):
        while True:
            try:
                with open('threat_response_token', 'r') as token_file:
                    access_token = token_file.read()
                    return access_token
            except FileNotFoundError:
                print('threat_response_token file not found, generating new token.')
                generate_token()
            break

def inspect(observable):
    '''Inspect the provided obsrevable and determine it's type
    '''
    inspect_url = 'https://visibility.amp.cisco.com/iroh/iroh-inspect/inspect'

    access_token = get_token()

    headers = {'Authorization':'Bearer {}'.format(access_token),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    inspect_payload = {'content':observable}
    inspect_payload = json.dumps(inspect_payload)

    response = SESSION.post(inspect_url, headers=headers, data=inspect_payload)
    return response

def enrich(observable):
    ''' Query the API for a observable
    '''
    enrich_url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/deliberate/observables'

    access_token = get_token()

    headers = {'Authorization':'Bearer {}'.format(access_token),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    response = SESSION.post(enrich_url, headers=headers, data=observable)

    return response

def unauthorized(response):
    ''' Check the status code of the response
    '''
    if response.status_code == 401 or response.status_code == 400:
        return True
    return False

def check_auth(function, param):
    ''' Query the API and validate authentication was successful
        If authentication fails, generate a new token and try again
    '''
    response = function(param)
    if unauthorized(response):
        print('Auth failed, generating new token.')
        generate_token()
        return function(param)
    return response

def query(observable):
    ''' Pass the functions and parameters to check_auth to query the API
        Return the final response
    '''
    response = check_auth(inspect, observable)
    inspect_output = response.text
    response = check_auth(enrich, inspect_output)
    return response

def main():
    ''' Main script logic
    '''
    try:
        observable = sys.argv[1]
    except IndexError:
        observable = input('Enter an observable: ')

    response = query(observable)
    response_json = response.json()

    for module in response_json['data']:
        module_name = module['module']
        if 'verdicts' in module['data'] and module['data']['verdicts']['count'] > 0:
            docs = module['data']['verdicts']['docs']
            for doc in docs:
                observable_value = doc['observable']['value']
                disposition = doc.get('disposition', 'None')
                disposition_name = doc.get('disposition_name', 'None')
                print('{:<23}{:<5}{:<13}{}'.format(module_name,
                                                   disposition,
                                                   disposition_name,
                                                   observable_value))

if __name__ == '__main__':
    main()
