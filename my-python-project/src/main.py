from flask import Flask
app = Flask(__name__)
from decorator import validate_token
#     

@app.route("/")
@validate_token('admin')
def hello_world():
    return "Hello, World!"

if __name__ == "__main__":
    app.run(debug=True)
