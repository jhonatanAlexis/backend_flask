from flask_pymongo import PyMongo

mongo = PyMongo()

def init_db(app): #esta funcion inicializa la base de datos
    mongo.init_app(app)

