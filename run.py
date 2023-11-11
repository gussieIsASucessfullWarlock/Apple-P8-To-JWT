import jwt
import datetime
from cryptography.hazmat.primitives import serialization

def get_apple_client_secret(team_id, client_id, key_id, p8_file_path):
    audience = "https://appleid.apple.com"
    issuer = team_id
    subject = client_id
    kid = key_id
    header = {
        "alg": "ES256",
        "kid": kid
    }
    claims = {
        "sub": subject,
        "nbf": int(datetime.datetime.now().timestamp()),
        "exp": int((datetime.datetime.now() + datetime.timedelta(days=180)).timestamp()),
        "iss": issuer,
        "aud": audience
    }
    with open(p8_file_path, "rb") as p8_file:
        private_key = serialization.load_pem_private_key(
            p8_file.read(),
            password=None
        )
    token = jwt.encode(claims, private_key, algorithm="ES256", headers=header)
    return token

team_id = input("Team ID: ")
client_id = input("Service ID: ")
key_id = input("Key ID: ")
p8_key = input("Path to .p8 file: ")

apple_client_secret = get_apple_client_secret(team_id, client_id, key_id, p8_key)
print(apple_client_secret)
