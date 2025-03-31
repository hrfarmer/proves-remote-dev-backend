import json
import os
import time

import jwt
import requests


def auth():
    try:
        with open("auth.pem", 'rb') as pem_file:
            signing_key = pem_file.read()

        payload = {
            # Issued at time
            'iat': int(time.time()),
            # JWT expiration time (10 minutes maximum)
            'exp': int(time.time()) + 600,
            
            # GitHub App's client ID
            'iss': os.getenv("GITHUB_CLIENT_ID")
        }

        encoded_jwt = jwt.encode(payload, signing_key, algorithm='RS256')

        response = requests.get(
            f"https://api.github.com/orgs/{os.getenv('GITHUB_ORG')}/installation",
            headers={
                "Authorization": f"Bearer {encoded_jwt}"
            },
            timeout=30
        )
        installation_id = response.json()['id']

        response = requests.post(f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {encoded_jwt}"
            },
            timeout=30
        )
        token_data = response.json()

        with open('.jwt', 'w', encoding='utf-8') as f:
            json.dump({
                'jwt': encoded_jwt,
                'installation_id': installation_id,
                'access_token': token_data['token']
            }, f)

        print("Successfully authenticated with GitHub")
    except Exception as e:
        print(f"Error authenticating with GitHub: {e}")
        return None
