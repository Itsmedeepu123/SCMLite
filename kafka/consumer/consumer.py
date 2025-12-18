from kafka import KafkaConsumer
from pymongo import MongoClient
import json
import time

# ================= Kafka Config =================
KAFKA_BROKER = "kafka:9092"        # Docker service name
KAFKA_TOPIC = "sensor_data"        # MUST match producer
CONSUMER_GROUP = "sensor-data-group"

# ================= MongoDB Config =================
MONGODB_URI = "mongodb+srv://deepa:deepa123@cluster0.ppja1aq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME = "projectfast"
COLLECTION_NAME = "datastream"

# ================= MongoDB Connection =================
print("[Consumer] Connecting to MongoDB...")
mongo_client = MongoClient(MONGODB_URI)
db = mongo_client[DB_NAME]
collection = db[COLLECTION_NAME]
print("[Consumer] MongoDB connected")

# ================= Kafka Consumer =================
print("[Consumer] Connecting to Kafka...")
consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_BROKER,
    group_id=CONSUMER_GROUP,
    auto_offset_reset="earliest",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

print(f"[Consumer] Listening on topic: {KAFKA_TOPIC}")

# ================= Consume Messages =================
try:
    for message in consumer:
        data = message.value
        print(f"[Consumer] Received: {data}")

        collection.insert_one(data)
        print("[Consumer] Inserted into MongoDB")

except KeyboardInterrupt:
    print("\n[Consumer] Stopped by user")

finally:
    consumer.close()
    mongo_client.close()
    print("[Consumer] Shutdown complete")
