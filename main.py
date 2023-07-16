from typing import Dict, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_authentication_response,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
    ResidentKeyRequirement,
    RegistrationCredential,
)

import json
import uvicorn
import secrets
import re

# Define the CORS origins that are allowed to access your API
pattern = r"project-exterior\.vercel\.app$"

origins = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://dev.project-exterior.com",
    re.compile(pattern=pattern)
]

app = FastAPI()

# Add the CORS middleware to app
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

class AuthenticatorSelection(BaseModel):
    authenticator_attachment: str
    resident_key: str = 'required'
    require_resident_key: bool = True

class RegistrationOptions(BaseModel):
    rp_id: str
    rp_name: str
    user_id: str
    user_name: str
    user_display_name: str
    timeout: int
    authenticator_selection: AuthenticatorSelection
    attestation: str

class RegisterCrendential(BaseModel):
    credential: Dict
    expected_challenge: str
    expected_origin: str
    expected_rp_id: Optional[str]
    require_user_verification: bool = True


class AuthenticationOptions(BaseModel):
   rp_id: str
   timeout: int = 12000
   credential_id: str
   user_verification: str = UserVerificationRequirement.REQUIRED

class AuthenticationCredential(BaseModel):
    credential: Dict
    expected_challenge: str
    expected_origin: str
    expected_rp_id: Optional[str]
    credential_public_key: str
    credential_current_sign_count: int = 0
    require_user_verification: bool = True
   

@app.post('/register/credential')
def create_registration_credential_options(options: RegistrationOptions):
  try:
    registration_options = generate_registration_options(
      rp_id=options.rp_id,
      rp_name=options.rp_name,
      user_id=options.user_id,
      user_name=options.user_name,
      user_display_name=options.user_display_name,
      attestation=AttestationConveyancePreference.DIRECT,
      authenticator_selection=options.authenticator_selection,
      challenge=secrets.token_hex(),
      timeout=12000,
    )

    return registration_options
  except Exception as e:
    print(str(e))
    raise HTTPException(status_code=500, detail={ 'detail': str(e) })

@app.post('/register/credential/verify')
def verify_registration_credential(credential: RegisterCrendential):
   try:
      registration_verification = verify_registration_response(
        credential=RegistrationCredential.parse_raw(json.dumps(credential.credential)),
        expected_challenge=base64url_to_bytes(credential.expected_challenge),
        expected_origin=credential.expected_origin,
        expected_rp_id=credential.expected_rp_id,
        require_user_verification=credential.require_user_verification
      )

      return jsonable_encoder(registration_verification)
   except Exception as e:
      print(str(e))
      raise HTTPException(status_code=500, detail={ 'detail': str(e) })
   

@app.post('/auth/credential')
def create_authentication_options(options: AuthenticationOptions):
  try:
    print(options)
    authentication_options = generate_authentication_options(
       rp_id=options.rp_id,
       challenge=secrets.token_hex(),
       timeout=options.timeout,
       allow_credentials=[PublicKeyCredentialDescriptor(id=options.credential_id, transports=[AuthenticatorTransport.INTERNAL])],
       user_verification=options.user_verification,
    )
    return authentication_options
  except Exception as e:
    print(str(e))
    raise HTTPException(status_code=500, detail={ 'detail': str(e) })
  

@app.post('/auth/credential/verify')
def verify_authentication_credential(credential: AuthenticationCredential):
  try:
     authentication_verification = verify_authentication_response(
        credential=credential.credential,
        expected_challenge=base64url_to_bytes(credential.expected_challenge),
        expected_rp_id=credential.expected_rp_id,
        expected_origin=credential.expected_origin,
        credential_public_key=credential.credential_public_key,
        credential_current_sign_count=credential.credential_current_sign_count,
        require_user_verification=credential.require_user_verification
     )

     return jsonable_encoder(authentication_verification)
  except Exception as e:
    print(str(e))
    raise HTTPException(status_code=500, detail={ 'detail': str(e) })
    
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)