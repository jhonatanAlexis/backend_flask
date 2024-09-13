from flask import Flask, request, jsonify #request es de las peticiones y jsonfy para convertir a json
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from model import mongo, init_db
from config import Config
from flask_bcrypt import Bcrypt
from bson.json_util import ObjectId #esta importación es útil si necesitas trabajar con IDs de MongoDB en tu aplicación Flask

app = Flask(__name__) #inicializamos la aplicacion diciendole que es de flask
app.config.from_object(Config) #Esto le dice a nuestra aplicación que cargue las configuraciones desde la clase Config

bcrypt = Bcrypt(app) #inicializa bcrypt
jwt = JWTManager(app) #inicializa jwt

init_db(app) #inicializa el acceso a mongo

#definir endpoint para registrar usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() #lee los datos que le pase y los guarda en data
    email = data.get('email') # Extrae el valor asociado con la clave
    username = data.get('username')
    password = data.get('password')

    #busca un usuario en la base de datos por su email
    if mongo.db.users.find_one({ #users es la coleccion de la base de datos
        'email': email #'email' es lo que esta en la coleccion y email es lo que quiero buscar
    }):
        #y si ya existe devuelve mensaje y error 400
        return jsonify({
            "msg": "Ese usuario ya existe"
        }), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') #hace hash a la contraseña

    #crea un nuevo usuario en la base de datos (mongo.db.users.insert_one devueve un objeto con 2 propiedades, "acknowledge" que es si se guardo correctamente y el id del documento insertado)
    result = mongo.db.users.insert_one({
        'email': email,
        'username': username,
        'password': hashed_password
    })
    if(result.acknowledged):
        return jsonify({
            "msg": "Usuario creado correctamente"
        }), 201
    else:
        return jsonify({
            "msg": "Error al crear el usuario"
        }), 400
    
#definir endpoint para login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = mongo.db.users.find_one({
        'email': email
    })
    #verifica si el usuario existe y la contraseña es correcta, crea un token jwt
    if user and bcrypt.check_password_hash(user['password'], password): #user['password'] es la contraseña almacenada en la base de datos y password es la que recupero
        access_token = create_access_token(identity=str(user["_id"])) #identity le dice al sistema qué dato único del usuario usar como identificador o sea el _id que da mongo y este lo convertimos en cadena por convenciencia
        return jsonify(access_token = access_token), 200 #devuelve el token
    else:
        return jsonify({
            "msg": "Credenciales incorrectas"
        }), 401
    
@app.route('/me', methods=['GET'])
@jwt_required() #creamos endpoint protegido
def me():
    data = request.get_json()
    username = data.get('username')

    usuario = mongo.db.users.find_one({
        'username': username
    }, {
        'password': 0 #excluir el password para que no se deduelva
    })

    if usuario:
        usuario["_id"]=str(usuario["_id"]) #convierte el id en cadena de texto para cambiar el id
        return jsonify({
            "usuario:": usuario
        }), 200
    else:
        return jsonify({
            "msg": "Usuario no encontrado"
        }), 404

# Endpoint para buscar usuario por el id del token
@app.route('/userIdData', methods=['GET'])
@jwt_required() 
def userIdData():
    userId = get_jwt_identity() #busca el identificador unico (id) desde el jwt

    userId = ObjectId(userId) #convertimos el user a objeto para poder hacer la busqueda (estaba en str)

    user = mongo.db.users.find_one({
        '_id': userId
    },{
        'password': 0
    })

    if user:
        user['_id'] = str(user['_id']) 
        return jsonify({
            "msj": "Usuario encontrado",
            "usuario": user
        }), 200
    else:
        return jsonify({
            "msj": "Usuario no encontrado"
        }), 404
    
# endpoint crear coches por usuario
@app.route('/userCar', methods=['POST'])
@jwt_required()
def userCar():
    car_data = request.get_json()

    userId = get_jwt_identity()
    userId = ObjectId(userId)

    car_data['_id'] = userId #le asignamos el id del coche al id del usuario adquirido desde el jwt

    result = mongo.db.cars.insert_one(car_data) #inserta los datos que quieras del coche (no lo estableci cuales son)

    if result.acknowledged:
        return jsonify({
            "msj": "Coche creado con exito",
            "coche": car_data,
            "id_coche": str(result.inserted_id) #inserta el id del result (coche)
        }), 200
    else:
        return jsonify({
            "msj": "Error al crear el coche"
        }), 400

# El argumento debug=True inicia el servidor web de desarrollo de Flask con el modo de 
# depuración activado, lo que permite ver errores detallados y reiniciar automáticamente
# el servidor cuando se realizan cambios en el código. (SERIA COMO EL NODEMON)
if __name__ == '__main__': # app.run hace que la aplicación comience a funcionar cuando ejecutas
    app.run(debug=True)