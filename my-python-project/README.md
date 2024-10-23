# My Python Project

This is a Python project that contains the main logic and functionality of the project.

## Installation

1. Clone the repository: `git clone https://github.com/your-username/my-python-project.git`
2. Navigate to the project directory: `cd my-python-project`
3. Install the project dependencies: `pip install -r requirements.txt`

## Usage

To run the project, execute the following command:

```bash
python my_python_project/main.py
```

## Testing

To run the unit tests for the project, execute the following command:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## `validate_token`

Decorator to validate the presence and content of an authorization token in the request headers.

### Arguments
- `required_role` (str): The role required to access the decorated function.

### Returns
- `function`: The decorated function with token validation.

### Description
The decorator performs the following checks:
1. Ensures the 'Authorization' token is present in the request headers.
2. Decodes the JWT token using a predefined secret and issuer URL.
3. Checks if the 'User_Impersonation' scope is present in the token data.
4. Verifies if the required role is present in the token data.

If any of these checks fail, it returns a JSON response with an appropriate error message and a 403 status code.

### Example
```python
@validate_token('admin')
def protected_route():
    return jsonify({"message": "This is a protected route"})