import jwt
import requests
from jwt.algorithms import RSAAlgorithm
from datetime import datetime

# Méthode qui décode un jeton JWT
# Ce jeton est un jeton provenant d'Azure Active Directory
# La méthode devra récupérer la clé publique via le point d'entré https://login.microsoftonline.com/common/discovery/keys
# et devra utiliser l'algorithme RS256 pour décoder le jeton
# Il devra également invalider le jeton si la date est dépassée, si l'audience ou l'issuer ne correspond pas à la configuration

def decode_jwt(token, audience, issuer):
    # Récupérer les clés publiques depuis Azure AD
    jwks_url = "https://login.microsoftonline.com/common/discovery/keys"
    jwks = requests.get(jwks_url).json()
    
    # Extraire la clé publique correspondant au kid du token
    headers = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == headers['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
            break
    
    if not rsa_key:
        raise Exception("Public key not found.")
    
    # Décoder le token
    try:
        decoded_token = jwt.decode(
            token,
            RSAAlgorithm.from_jwk(rsa_key),
            algorithms=['RS256'],
            audience=audience,
            issuer=issuer
        )
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired.")
    except jwt.InvalidTokenError as e:
        raise Exception(f"Invalid token: {e}")
    
    return decoded_token