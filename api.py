from fastapi import FastAPI, Request, HTTPException, Header
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.webauthn import AuthenticatorSelectionCriteria, UserVerificationRequirement, RegistrationResponse
from fido2 import cbor
from fido2.webauthn import CollectedClientData

from fido2.utils import websafe_encode
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fido2.client import AttestationObject
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






def base64url_to_bytes(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def b64url_decode(data):
    # Add padding if needed
    data += '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


@app.post("/api/register/complete")
async def register_complete(request: Request):
    body = await request.json()
    username = body["username"]
    credential = body["credential"]

    user_entry = USERS.get(username)

    if not user_entry:
        return {"error": "No registration in progress for this user"}

    client_data_bytes = b64url_decode(credential["response"]["clientDataJSON"])
    attestation_bytes = b64url_decode(credential["response"]["attestationObject"])

    client_data = CollectedClientData(client_data_bytes)
    att_obj = AttestationObject(attestation_bytes)

    #auth_data = Fido2Server.register_complete(user_entry["state"], client_data, att_obj)
    auth_data = server.register_complete(user_entry["state"], credential)

    # Save credential
    CREDENTIALS[username] = auth_data.credential_data
    print(auth_data.credential_data, flush=True)
    return {"status": "ok"}




@app.post("/api/auth/begin")
async def auth_begin(request: Request):
    body = await request.json()
    username = body["username"]

    if username not in CREDENTIALS:
        raise HTTPException(status_code=400, detail="No credentials")

    auth_data, state = server.authenticate_begin([CREDENTIALS[username]])
    USERS[username]["auth_state"] = state
    print(cbor.encode(auth_data),flush=True)
    return Response(content=cbor.encode(auth_data), media_type="application/cbor")






def b64url_decode(val: str) -> bytes:
    return base64.urlsafe_b64decode(val + '=' * (-len(val) % 4))

def b64url_encode(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b'=').decode('ascii')


@app.post("/api/auth/complete")
async def auth_complete(request: Request):
    body = await request.json()
    username = request.headers.get("x-username")

    if not username or username not in USERS:
        raise HTTPException(status_code=400, detail="Invalid username")

    raw_id: bytes = b64url_decode(body["rawId"])
    id_str: str = b64url_encode(raw_id)  # Ensure it's a string

    # Construct response object
    client_data = {
        "id": id_str,                   # must be string!
        "rawId": raw_id,                # must be bytes!
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

    client_data["id"] = websafe_decode(client_data["id"])

    auth_data = server.authenticate_complete(
        USERS[username]["auth_state"],
        [CREDENTIALS[username]],
        client_data,
    )

    return {"authenticated": True}
