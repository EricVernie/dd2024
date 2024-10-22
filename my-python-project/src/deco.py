# Le décorateur doit valider le scope User_Impersonation
# Si le scope n'est pas présent dans le Jeton d'accès, le décorateur doit retourner une erreur 403
# Si le scope est présent, le décorateur doit appeler la méthode read_token 
# Vérifier dans le jeton la présence du claim roles 
# Vérifier si dans le jeton il y a la présence du rôle passé en paramètre
# Si le rôle n'est pas présent, le décorateur doit retourner une erreur 403
# Si le rôle est présent, le décorateur doit appeler la méthode passée en paramètre

from functools import wraps
from flask import request, jsonify
from decodetoken import decode_jwt


__all__ = ['validate_token']

def validate_token(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({"error": "Token is missing"}), 403

            # Simulate reading the token
            # token_data = read_token(token)
            token_data = decode_jwt(token,
                                    'ec5d10ef-87c0-41a2-a22d-a8a54d5cd677', 
                                    'https://login.microsoftonline.com/312e8fa5-668a-4188-91bf-86b88d0c392a/v2.0')

            if 'User_Impersonation' not in token_data.get('scope', []):
                return jsonify({"error": "User_Impersonation scope is missing"}), 403

            if required_role not in token_data.get('roles', []):
                return jsonify({"error": f"Required role {required_role} is missing"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def read_token(token):
    # Simulate token reading and validation
    # This should be replaced with actual token parsing logic
    return {
        "scope": ["User_Impersonation"],
        "roles": ["admin", "user"]
    }