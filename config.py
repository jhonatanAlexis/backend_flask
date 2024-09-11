import os #se usa para trabajar con variables de entorno
from dotenv import load_dotenv

load_dotenv() #lee el archivo .env y carga las variables que contiene para que puedan ser usadas en el código

class Config:
    MONGO_URI = os.getenv("MONGO_URI")  #Obtiene el valor de la variable de entorno MONGO_URI (que esta en el archivo .env) y lo guarda 
    JWT_SECRET_KEY = os.getenv("JWT_SECRET") # Hace lo mismo para la variable JWT_SECRET_KEY (TIENE QUE SER ASI)