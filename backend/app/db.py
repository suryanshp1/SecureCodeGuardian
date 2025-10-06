import os
from pymongo import MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017")
client = MongoClient(MONGO_URI)
db = client.get_database("codeguardian")
results = db.get_collection("results")