from flask import Flask
app = Flask(__name__)
from decorator import validate_token

def main():
    # TODO: Add your main logic here
    pass

if __name__ == "__main__":
    main()
    

    @app.route("/")
    @validate_token('admin')
    def hello_world():
        return "Hello, World!"

    if __name__ == "__main__":
        app.run(debug=True)
