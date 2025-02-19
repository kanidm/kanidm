"""User Auth Token related widgets"""
# pylint: disable=too-few-public-methods

import base64
from datetime import datetime, timedelta, timezone

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from authlib.jose import JsonWebSignature  # type: ignore
from pydantic import ConfigDict, BaseModel, Field

from . import TOKEN_PATH


class JWSHeader(BaseModel):
    """JWS Header Parser"""

    class JWSHeaderJWK(BaseModel):
        """JWS Header Sub-bit"""

        kty: str
        crv: str
        x: str
        y: str
        alg: str
        use: str

    alg: str
    typ: str
    jwk: JWSHeaderJWK
    model_config = ConfigDict(arbitrary_types_allowed=True)


class JWSPayload(BaseModel):
    """JWS Payload parser"""

    session_id: str
    auth_type: str
    # TODO: work out the format of the expiry
    # example expiry: 2022,265,28366,802525000
    expiry: List[int]  # [year, day of year, something?]
    uuid: str
    name: str
    displayname: str
    spn: str
    mail_primary: Optional[str] = None
    lim_uidx: bool
    lim_rmax: int
    lim_pmax: int
    lim_fmax: int

    @property
    def expiry_datetime(self) -> datetime:
        """parse the expiry and return a datetime object"""
        year, day, seconds, _ = self.expiry
        retval = datetime(year=year, month=1, day=1, second=0, hour=0, tzinfo=timezone.utc)
        # day - 1 because we're already starting at day 1
        retval += timedelta(days=day - 1, seconds=seconds)
        return retval


class JWS:
    """JWS parser"""

    def __init__(self, raw: str) -> None:
        """raw is the raw string version of the JWS"""

        data = self.parse(raw)
        self.header = data[0]
        self.payload = data[1]
        self.signature = data[2]

    @classmethod
    def parse(cls, raw: str) -> Tuple[JWSHeader, JWSPayload, bytes]:
        """parse a raw JWS"""
        if "." not in raw:
            raise ValueError("Invalid number of segments, there's no . in the raw JWS")
        split_raw = raw.split(".")
        if len(split_raw) != 3:
            raise ValueError("Invalid number of segments")

        raw_header = split_raw[0]
        logging.debug("Parsing header: %s", raw_header)
        padded_header = raw_header + "=" * divmod(len(raw_header), 4)[0]
        decoded_header = base64.urlsafe_b64decode(padded_header)
        logging.debug("decoded_header=%s", decoded_header)
        header = JWSHeader.model_validate(json.loads(decoded_header.decode("utf-8")))
        logging.debug("header: %s", header)

        raw_payload = split_raw[1]
        logging.debug("Parsing payload: %s", raw_payload)
        padded_payload = raw_payload + "=" * divmod(len(raw_payload), 4)[1]
        payload = JWSPayload.model_validate_json(base64.urlsafe_b64decode(padded_payload))

        raw_signature = split_raw[2]
        logging.debug("Parsing signature: %s", raw_signature)
        padded_signature = raw_signature + "=" * divmod(len(raw_signature), 4)[1]
        signature = base64.urlsafe_b64decode(padded_signature)

        return header, payload, signature


class ConfigInstance(BaseModel):
    """Configuration Instance"""

    keys: Dict[str, Dict[str, Any]] = Field(dict())
    tokens: Dict[str, str] = Field(dict())


class TokenStore(BaseModel):
    """Represents the user auth tokens, so we can load them from the user store"""

    instances: Dict[str, ConfigInstance] = Field({"": ConfigInstance.model_construct()})

    def save(self, filepath: Path = TOKEN_PATH) -> None:
        """saves the cached tokens to disk"""
        data = self.model_dump_json(indent=2)
        with filepath.expanduser().resolve().open(mode="w", encoding="utf-8") as file_handle:
            file_handle.write(data)

    def load(self, overwrite: bool = True, filepath: Path = TOKEN_PATH) -> None:
        """Loads the tokens from from the store and caches them in memory - by default
        from the local user's store path, but you can point it at any file path.

        If overwrite=False, then it will add them to the existing in-memory store"""
        token_path = filepath.expanduser().resolve()
        if not token_path.exists():
            tokens = TokenStore.model_validate({})
        else:
            with token_path.open(encoding="utf-8") as file_handle:
                tokens = TokenStore.model_validate_json(file_handle.read())

        if overwrite:
            self = TokenStore.model_validate(tokens)
        else:
            # naive update
            for instance, value in tokens.instances.items():
                if instance not in self.instances:
                    self.instances[instance] = value
        # TODO: make this work properly
        # self.validate_tokens()

        logging.debug(tokens.model_dump_json(indent=2))

    def validate_tokens(self) -> None:
        """validates the JWS tokens for format, not their signature - PRs welcome"""
        for instance_name, instance in self.instances.items():
            for username, token in instance.tokens.items():
                logging.debug("Parsing instance=%s username=%s", instance_name, username)
                # TODO: Work out how to get the validation working. We probably shouldn't be worried about this since we're using it for auth...
                logging.debug(JsonWebSignature().deserialize_compact(s=token, key=None))

    def token_info(self, username: str, instance: Optional[str] = None) -> Optional[JWSPayload]:
        """grabs a token and returns a complex object object"""

        instance = instance if instance is not None else ""

        if instance not in self.instances:
            logging.error("No instance found for %s", instance)
            return None

        if not hasattr(self.instances[instance], "tokens"):
            logging.error("No tokens found for instance '%s'", instance)
            return None

        token = self.instances[instance].tokens.get(username)
        if token is None:
            logging.debug("No token found for %s", username)
            return None
        parsed_object = JsonWebSignature().deserialize_compact(s=token, key=None)
        logging.debug(parsed_object)
        return JWSPayload.model_validate_json(parsed_object.payload)
