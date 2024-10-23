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
    """
    Decorator to validate the presence and content of an authorization token in the request headers.

    Args:
        required_role (str): The role required to access the decorated function.

    Returns:
        function: The decorated function with token validation.

    The decorator performs the following checks:
    1. Ensures the 'Authorization' token is present in the request headers.
    2. Decodes the JWT token using a predefined secret and issuer URL.
    3. Checks if the 'User_Impersonation' scope is present in the token data.
    4. Verifies if the required role is present in the token data.

    If any of these checks fail, it returns a JSON response with an appropriate error message and a 403 status code.
    """
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
    """
    Simulates the reading and validation of a token.

    This function is a placeholder and should be replaced with actual token parsing logic.
    It returns a dictionary containing the scope and roles associated with the token.

    Args:
        token (str): The token to be read and validated.

    Returns:
        dict: A dictionary with the following keys:
            - "scope" (list): A list of scopes associated with the token.
            - "roles" (list): A list of roles associated with the token.
    """
    # Simulate token reading and validation
    # This should be replaced with actual token parsing logic
    return {
        "scope": ["User_Impersonation"],
        "roles": ["admin", "user"]
    }