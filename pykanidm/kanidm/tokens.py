""" User Auth Token related widgets """
# pylint: disable=too-few-public-methods

import base64
from datetime import datetime, timedelta, timezone

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from authlib.jose import JsonWebSignature # type: ignore
from pydantic import BaseModel

from . import TOKEN_PATH

class JWSHeader(BaseModel):
    """ JWS Header Parser """
    class JWSHeaderJWK(BaseModel):
        """ JWS Header Sub-bit"""
        kty: str
        crv: str
        x: str
        y: str
        alg: str
        use: str

    alg: str
    typ: str
    jwk: JWSHeaderJWK

    class Config:
        """ Configure the pydantic class """
        arbitrary_types_allowed = True

class JWSPayload(BaseModel):
    """ JWS Payload parser"""
    session_id: str
    auth_type: str
    # TODO: work out the format of the expiry
    # example expiry: 2022,265,28366,802525000
    expiry: List[int] # [year, day of year, something?]
    uuid: str
    name: str
    displayname: str
    spn: str
    mail_primary: Optional[str]
    lim_uidx: bool
    lim_rmax: int
    lim_pmax: int
    lim_fmax: int

    @property
    def expiry_datetime(self) -> datetime:
        """ parse the expiry and return a datetime object """
        year, day, seconds, _ = self.expiry
        retval = datetime(year=year, month=1, day=1, second=0, hour=0, tzinfo=timezone.utc)
        # day - 1 because we're already starting at day 1
        retval += timedelta(days=day-1, seconds=seconds)
        return retval


class JWS:
    """ JWS parser """
    def __init__(self, raw: str) -> None:
        """ raw is the raw string version of the JWS """

        data = self.parse(raw)
        self.header = data[0]
        self.payload = data[1]
        self.signature = data[2]

    @classmethod
    def parse(cls, raw: str) -> Tuple[JWSHeader, JWSPayload, bytes]:
        """ parse a raw JWS """
        if "." not in raw:
            raise ValueError("Invalid number of segments, there's no . in the raw JWS")
        split_raw = raw.split(".")
        if len(split_raw) != 3:
            raise ValueError("Invalid number of segments")

        raw_header = split_raw[0]
        logging.debug("Parsing header: %s", raw_header)
        padded_header = raw_header + "="*divmod(len(raw_header),4)[0]
        decoded_header = base64.urlsafe_b64decode(padded_header)
        logging.debug("decoded_header=%s", decoded_header)
        header = JWSHeader.parse_obj(json.loads(decoded_header.decode("utf-8")))
        logging.debug("header: %s", header)

        raw_payload = split_raw[1]
        logging.debug("Parsing payload: %s", raw_payload)
        padded_payload = raw_payload + "="*divmod(len(raw_payload),4)[1]
        payload = JWSPayload.parse_raw(base64.urlsafe_b64decode(padded_payload))

        raw_signature = split_raw[2]
        logging.debug("Parsing signature: %s", raw_signature)
        padded_signature = raw_signature + "="*divmod(len(raw_signature),4)[1]
        signature = base64.urlsafe_b64decode(padded_signature)

        return header, payload, signature


class TokenStore(BaseModel):
    """ Represents the user auth tokens, can load them from the user store """
    __root__: Dict[str, str] = {}

    # TODO: one day work out how to type the __iter__ on TokenStore properly. It's some kind of iter() that makes mypy unhappy.
    def __iter__(self) -> Any:
        """ overloading the default function """
        for key in self.__root__.keys():
            yield key

    def __getitem__(self, item: str) -> str:
        """ overloading the default function """
        return self.__root__[item]

    def __delitem__(self, item: str) -> None:
        """ overloading the default function """
        del self.__root__[item]

    def __setitem__(self, key: str, value: str) -> None:
        """ overloading the default function """
        self.__root__[key] = value

    def save(self, filepath: Path = TOKEN_PATH) -> None:
        """ saves the cached tokens to disk """
        data = json.dumps(self.__root__, indent=2)
        with filepath.expanduser().resolve().open(mode='w', encoding="utf-8") as file_handle:
            file_handle.write(data)

    def load(self, overwrite: bool=True, filepath: Path = TOKEN_PATH) -> Dict[str,str]:
        """ Loads the tokens from from the store and caches them in memory - by default
            from the local user's store path, but you can point it at any file path.

            Will return the current cached store.

            If overwrite=False, then it will add them to the existing in-memory store """
        token_path = filepath.expanduser().resolve()
        if not token_path.exists():
            tokens: Dict[str, str] = {}
        else:
            with token_path.open(encoding="utf-8") as file_handle:
                tokens = json.load(file_handle)

        if overwrite:
            self.__root__ = tokens
        else:
            for user in tokens:
                self.__root__[user] = tokens[user]

        self.validate_tokens()

        logging.debug(json.dumps(tokens, indent=4))
        return self.__root__

    def validate_tokens(self) -> None:
        """ validates the JWS tokens for format, not their signature - PRs welcome """
        for username in self.__root__:
            logging.debug("Parsing %s", username)
            # TODO: Work out how to get the validation working. We probably shouldn't be worried about this since we're using it for auth...
            print(JsonWebSignature().deserialize_compact(s=self[username], key=None))

    def token_info(self, username: str) -> Optional[JWSPayload]:
        """ grabs a token and returns a complex object object """
        if username not in self:
            return None
        parsed_object = JsonWebSignature().deserialize_compact(s=self[username], key=None)
        logging.debug(parsed_object)
        return JWSPayload.parse_raw(parsed_object.payload)
