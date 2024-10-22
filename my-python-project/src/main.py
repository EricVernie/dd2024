from flask import Flask
from deco import validate_token

app = Flask(__name__)

#     

@app.route("/")
@validate_token('admin')
def hello_world():
    return "Hello, World!"

if __name__ == "__main__":
    app.run(debug=True)
