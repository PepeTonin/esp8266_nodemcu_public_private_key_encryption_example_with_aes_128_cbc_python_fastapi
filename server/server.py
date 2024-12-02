from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import base64
import json

from db import initDb, addRead
from utils_crypt import (
    encrypt_rsa_public_key,
    store_client_public_key,
    generate_aes_key,
    store_shared_aes_key,
    decrypt_aes,
)

app = FastAPI()


class ReadingReq(BaseModel):
    iv: str
    encrypted_data: str


class HandshakeReq(BaseModel):
    public_key: str


@app.on_event("startup")
def on_startup():
    initDb()


@app.post("/readings", status_code=201)
async def create_reading(request: ReadingReq):
    iv_bytes = bytes.fromhex(request.iv)
    encrypted_data_bytes = bytes.fromhex(request.encrypted_data)
    decrypted_data = decrypt_aes(iv_bytes, encrypted_data_bytes)
    try:
        read = json.loads(decrypted_data.decode("utf-8"))
        addRead(read["device_id"], read["current"], read["power"])
        return JSONResponse(
            content={"response": "Reading added successfully"}, status_code=201
        )
    except:
        return JSONResponse(
            content={"response": "Error adding reading to database"}, status_code=500
        )


@app.post("/handshake", status_code=200)
async def handshake(request: HandshakeReq):
    store_client_public_key(request.public_key)
    shared_aes_key_bytes = generate_aes_key()
    shared_aes_key_hex = shared_aes_key_bytes.hex()
    store_shared_aes_key(shared_aes_key_hex)
    encrypted_aes_key_bytes = encrypt_rsa_public_key(shared_aes_key_bytes)
    encrypted_aes_key_base64 = base64.b64encode(encrypted_aes_key_bytes)
    response = {
        "encrypted_aes_key": encrypted_aes_key_base64,
    }
    return {"response": response}
