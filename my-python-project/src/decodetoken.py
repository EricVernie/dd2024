import jwt
import requests
from datetime import datetime

def decode_jwt(token, audience, issuer):
    """
    Decode a JSON Web Token (JWT) using the public keys from Azure AD.

    Args:
        token (str): The JWT to decode.
        audience (str): The expected audience of the token.
        issuer (str): The expected issuer of the token.

    Returns:
        dict: The decoded token if the token is valid.

    Raises:
        Exception: If the public key is not found.
        jwt.ExpiredSignatureError: If the token has expired.
        jwt.InvalidTokenError: If the token is invalid.
    """
    # Fetch the public keys from Azure AD
    jwks_url = "https://login.microsoftonline.com/common/discovery/keys"
    response = requests.get(jwks_url)
    jwks = response.json()

    # Get the header from the token
    unverified_header = jwt.get_unverified_header(token)

    # Choose the key based on the kid in the header
    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    if rsa_key:
        try:
            # Decode the token
            decoded_token = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=issuer
            )
            return decoded_token
        except jwt.ExpiredSignatureError:
            print("Le jeton a expiré")
        except jwt.InvalidTokenError:
            print("Jeton invalide")
    else:
        print("Clé publique non trouvée")
        raise Exception("Clé publique non trouvée")
        

# Exemple d'utilisation
if __name__ == "__main__":
    token = "votre_jwt_token"
    audience = "votre_audience"
    issuer = "votre_issuer"
    result = decode_jwt(token, audience, issuer)
    print(result)