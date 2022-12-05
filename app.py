"""REsources Used
https://rahmanfadhil.com/flask-rest-api/
https://dev.to/paurakhsharma/flask-rest-api-part-3-authentication-and-authorization-5935
https://www.digitalocean.com/community/tutorials/how-to-use-one-to-many-database-relationships-with-flask-sqlalchemy
https://stackoverflow.com/questions/31444036/runtimeerror-working-outside-of-application-context
https://stackoverflow.com/questions/71065768/how-to-generate-hs256-secret-key-in-python-flask-jwt-extended
https://stackoverflow.com/questions/62207824/typeerror-wrapper-got-an-unexpected-keyword-argument-nam-while-using-jwt-r
"""
from flask import Flask, request
from flask_jwt_extended import jwt_required
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_restful import Api, Resource
import datetime
from flask_migrate import Migrate
from flask_bcrypt import generate_password_hash, check_password_hash, Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret-key"  # Change this!
app.config["JWT_ALGORITHM"] = "HS256"

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:UPbeat123@localhost:5432/flask_posts_db'  # new
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.app_context().push()
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# to set env variable run command >> set ENV_FILE_LOCATION=./.env

# db.create_all()
# Run in terminal
#     python
#     from app import app
#     from app import db,
#     db.create_all()
api = Api(app)

ma = Marshmallow(app)


# models
class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    content = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return '<Post %s>' % self.title


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    email = db.Column(db.String(80), index=True, unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=True)

    def __init__(self, **kwargs):
        """
        The function takes in a dictionary of keyword arguments and assigns the values to the class
        attributes
        """
        self.username = kwargs.get("username")
        self.email = kwargs.get("email")
        self.password = kwargs.get("password")
        self.last_name = kwargs.get("last_name")
        self.first_name = kwargs.get("first_name")
        self.created = kwargs.get("created")

    def __repr__(self):
        """
        The __repr__ function is used to return a string representation of the object
        :return: The username of the user.
        """
        return "<User {}>".format(self.username)

    def hash_password(self):
        """
        It takes the password that the user has entered, hashes it, and then stores the hashed password in
        the database
        """
        self.password = generate_password_hash(self.password).decode("utf8")

    def check_password(self, password):
        """
        It takes a plaintext password, hashes it, and compares it to the hashed password in the database

        :param password: The password to be hashed
        :return: The password is being returned.
        """
        return check_password_hash(self.password, password)


# signup
class LoginApi(Resource):
    def post(self):
        body = request.get_json()
        user = User.query.filter(User.email==body.get('email')).first()
        authorized = user.check_password(body.get('password'))
        if not authorized:
            return {'error': 'Email or password invalid'}, 401

        expires = datetime.timedelta(days=7)
        access_token = create_access_token(identity=str(user.id), expires_delta=expires)
        return {'token': access_token}, 200


# serializing
class PostSchema(ma.Schema):
    class Meta:
        fields = ("id", "title", "content", "user_id")
        model = Post


post_schema = PostSchema()
posts_schema = PostSchema(many=True)


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "first_name", "last_name", "email", "password", "created")
        model = User


user_schema = UserSchema()
users_schema = UserSchema(many=True)


# routes
class PostListResource(Resource):
    def get(self):
        posts = Post.query.all()
        return posts_schema.dump(posts)

    @jwt_required()
    def post(self):
        new_post = Post(
            title=request.json['title'],
            content=request.json['content'],
            user_id=request.json['user_id']
        )
        db.session.add(new_post)
        db.session.commit()
        return post_schema.dump(new_post)


class UserListResource(Resource):
    def get(self):
        users = User.query.all()
        return users_schema.dump(users)

    @jwt_required()
    def post(self):
        new_user = User(
            username=request.json['username'],
            email=request.json['email'],
            password=request.json['password'],
            first_name=request.json['first_name'],
            last_name=request.json['last_name'],
            # created=request.json['created']
        )
        new_user.hash_password()
        db.session.add(new_user)
        db.session.commit()
        return user_schema.dump(new_user)


class PostResource(Resource):
    def get(self, post_id):
        post = Post.query.get_or_404(post_id)
        return post_schema.dump(post)

    @jwt_required()
    def patch(self, post_id):
        post = Post.query.get_or_404(post_id)

        if 'title' in request.json:
            post.title = request.json['title']
        if 'content' in request.json:
            post.content = request.json['content']
        if 'user_id' in request.json:
            post.user_id = request.json['user_id']

        db.session.commit()
        return post_schema.dump(post)

    @jwt_required()
    def delete(self, post_id):
        post = Post.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()
        return '', 204


class UserResource(Resource):
    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        return user_schema.dump(user)

    @jwt_required()
    def patch(self, user_id):
        user = User.query.get_or_404(user_id)

        if 'username' in request.json:
            user.username = request.json['username']
        if 'email' in request.json:
            user.email = request.json['email']
        if 'first_name' in request.json:
            user.first_name = request.json['first_name']
        if 'last_name' in request.json:
            user.last_name = request.json['last_name']
        if 'password' in request.json:
            user.password = request.json['password']

        db.session.commit()
        return user_schema.dump(user)

    @jwt_required()
    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return '', 204


# User Posts resource
class UserPostResource(Resource):
    def get(self, user_id):
        user_posts = Post.query.join(User).filter(Post.user_id == user_id).all()
        # user_posts = Post.query.filter(Post.user_id == user_id)
        print(user_posts)
        return posts_schema.dump(user_posts)


api.add_resource(PostListResource, '/posts')
api.add_resource(PostResource, '/posts/<int:post_id>')
api.add_resource(UserListResource, '/users')
api.add_resource(UserResource, '/users/<int:user_id>')
api.add_resource(UserPostResource, '/users/<int:user_id>/posts')
api.add_resource(LoginApi, '/login')


# api.add_resource(UserListResource, '/signup')


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
