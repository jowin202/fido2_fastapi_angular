from fastapi import FastAPI, Request, HTTPException, Header
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.webauthn import UserVerificationRequirement
from fido2 import cbor

from fido2.utils import websafe_encode
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fido2.utils import websafe_decode


import base64

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],  # Angular frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rp = PublicKeyCredentialRpEntity(id="localhost", name="Example RP")
server = Fido2Server(rp)

USERS = {}  # Replace with DB in real world
CREDENTIALS = {}

@app.post("/api/register/begin")
async def register_begin(request: Request):
    body = await request.json()
    username = body["username"]
    user_id = username.encode()

    user = {
        "id": user_id,
        "name": username,
        "displayName": username,
    }

    registration_data, state = server.register_begin(
        user,
        credentials=[],
        user_verification=UserVerificationRequirement.PREFERRED
    )

    USERS[username] = {"id": user_id, "state": state}
    return Response(content=cbor.encode(registration_data), media_type="application/cbor")



@app.post("/api/register/complete")
async def register_complete(request: Request):
    body = await request.json()
    username = body["username"]
    credential = body["credential"]

    user_entry = USERS.get(username)

    if not user_entry:
        return {"error": "No registration in progress for this user"}

    auth_data = server.register_complete(user_entry["state"], credential)

    # Save credential
    CREDENTIALS[username] = auth_data.credential_data
    return {"status": "ok"}




@app.post("/api/auth/begin")
async def auth_begin(request: Request):
    body = await request.json()
    username = body["username"]

    if username not in CREDENTIALS:
        raise HTTPException(status_code=400, detail="No credentials")

    auth_data, state = server.authenticate_begin([CREDENTIALS[username]])
    USERS[username]["auth_state"] = state
    return Response(content=cbor.encode(auth_data), media_type="application/cbor")




def b64url_decode(val: str) -> bytes:
    return base64.urlsafe_b64decode(val + '=' * (-len(val) % 4))

@app.post("/api/auth/complete")
async def auth_complete(request: Request):
    body = await request.json()
    username = request.headers.get("x-username")

    if not username or username not in USERS:
        raise HTTPException(status_code=400, detail="Invalid username")

    raw_id: bytes = b64url_decode(body["rawId"])

    # Construct response object
    client_data = {
        "id": websafe_decode(body["rawId"]),    # must be string!
        "rawId": raw_id,                        # must be bytes!
        "type": body["type"],
        "response": {
            "clientDataJSON": b64url_decode(body["response"]["clientDataJSON"]),
            "authenticatorData": b64url_decode(body["response"]["authenticatorData"]),
            "signature": b64url_decode(body["response"]["signature"]),
            "userHandle": (
                b64url_decode(body["response"]["userHandle"])
                if body["response"].get("userHandle")
                else None
            ),
        },
    }

    auth_data = server.authenticate_complete(
        USERS[username]["auth_state"],
        [CREDENTIALS[username]],
        client_data,
    )

    return {"authenticated": True}
