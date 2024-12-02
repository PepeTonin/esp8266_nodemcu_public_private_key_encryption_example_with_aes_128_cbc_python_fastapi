import os
import mysql.connector
from dotenv import load_dotenv


load_dotenv()

db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
}


def getDbConnection():
    connection = mysql.connector.connect(**db_config)
    return connection


def initDb():
    connection = getDbConnection()
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS esp_reads (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_id VARCHAR(255) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        current FLOAT NOT NULL,
        power FLOAT NOT NULL
    );
    """
    cursor.execute(create_table_query)
    connection.commit()
    cursor.close()
    connection.close()


def addRead(device_id: str, current: float, power: float):
    connection = getDbConnection()
    cursor = connection.cursor()
    insert_query = """
    INSERT INTO esp_reads (device_id, current, power)
    VALUES (%s, %s, %s);
    """
    cursor.execute(insert_query, (device_id, current, power))
    connection.commit()
    cursor.close()
    connection.close()
