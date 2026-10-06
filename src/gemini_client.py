from dataclasses import dataclass
from typing import Optional

TRANSIENT_CODES = [408, 429, 500, 502, 503, 504]
TRANSIENT_NAMES = ["Timeout", "TimeoutException", "ReadTimeout", "ConnectTimeout", "WriteTimeout", "PoolTimeout",
                   "ConnectError", "ReadError", "WriteError", "RemoteProtocolError", "NetworkError", "ConnectionError",
                   "TimeoutError", "ServerError"]


class ModelCallError(Exception):
    def __init__(self, message, status=None):
        Exception.__init__(self, message)
        self.status = status


class TransientModelError(ModelCallError):
    pass


class PermanentModelError(ModelCallError):
    pass


@dataclass
class CallRecord:
    text: str
    finish_reason: Optional[str]
    block_reason: Optional[str]
    prompt_tokens: Optional[int]
    output_tokens: Optional[int]
    thinking_tokens: Optional[int]
    total_tokens: Optional[int]


def classify_exception(error):
    code = getattr(error, "code", None)
    if isinstance(code, int):
        if code in TRANSIENT_CODES:
            return "transient"
        return "permanent"
    for cls in type(error).__mro__:
        if cls.__name__ in TRANSIENT_NAMES:
            return "transient"
    return "permanent"


def redact(text, secret):
    text = str(text)
    if secret:
        text = text.replace(secret, "[redacted]")
    return text


def _field(obj, name):
    if obj is None:
        return None
    return getattr(obj, name, None)


def _enum_name(value):
    if value is None:
        return None
    name = getattr(value, "name", None)
    if name:
        return str(name)
    return str(value)


def read_response(response):
    text = ""
    try:
        got = response.text
        if got is not None:
            text = got
    except Exception:
        text = ""
    finish = None
    candidates = _field(response, "candidates")
    if candidates:
        finish = _enum_name(_field(candidates[0], "finish_reason"))
    block = _enum_name(_field(_field(response, "prompt_feedback"), "block_reason"))
    usage = _field(response, "usage_metadata")
    return CallRecord(
        text=text,
        finish_reason=finish,
        block_reason=block,
        prompt_tokens=_field(usage, "prompt_token_count"),
        output_tokens=_field(usage, "candidates_token_count"),
        thinking_tokens=_field(usage, "thoughts_token_count"),
        total_tokens=_field(usage, "total_token_count"),
    )


def make_sdk_client(api_key, timeout_seconds):
    from google import genai
    return genai.Client(api_key=api_key, http_options={"timeout": int(timeout_seconds * 1000)})


class GeminiClient:
    def __init__(self, model, system_prompt, temperature, max_output_tokens, seed, api_key=None, timeout_seconds=60, sdk_client=None):
        self.model = model
        self.api_key = api_key
        self.config = {
            "system_instruction": system_prompt,
            "temperature": temperature,
            "max_output_tokens": max_output_tokens,
            "seed": seed,
        }
        if sdk_client is None:
            sdk_client = make_sdk_client(api_key, timeout_seconds)
        self.sdk_client = sdk_client

    def generate(self, prompt):
        try:
            response = self.sdk_client.models.generate_content(model=self.model, contents=prompt, config=self.config)
        except Exception as error:
            kind = classify_exception(error)
            status = getattr(error, "code", None)
            message = type(error).__name__ + ": " + redact(error, self.api_key)
            if len(message) > 600:
                message = message[:600] + " ...[cut]"
            if kind == "transient":
                raise TransientModelError(message, status)
            raise PermanentModelError(message, status)
        return read_response(response)
