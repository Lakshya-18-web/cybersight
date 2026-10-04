"""LLM provider and model settings for Weeks 2 to 5.

Nothing here calls an API. Keys come from the environment or from a .env file in the project root,
and are never printed or written anywhere.

Two models are used so that Week 2 can compare a cheap one with a stronger one on the dev set:
  SMALL_MODEL   cheap and fast, the default for prompt iteration
  STRONG_MODEL  the stronger model, for the comparison run
Override either with SOC_SMALL_MODEL / SOC_STRONG_MODEL (in .env or the shell) without editing code.
"""
import os

PROVIDER = "gemini"
API_KEY_ENV = "GEMINI_API_KEY"

DEFAULT_SMALL_MODEL = "gemini-2.5-flash-lite"
DEFAULT_STRONG_MODEL = "gemini-2.5-pro"

# Settings every baseline run shares, so runs differ only by model and prompt.
TEMPERATURE = 0.0
MAX_OUTPUT_TOKENS = 1024
REQUEST_TIMEOUT_SECONDS = 60
MAX_RETRIES = 2

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")


def load_env(path=ENV_PATH):
    """Load KEY=VALUE lines from .env into os.environ without overriding variables that are already set.
    Returns True if a file was read."""
    if not os.path.exists(path):
        return False
    try:
        from dotenv import load_dotenv
        load_dotenv(path, override=False)
        return True
    except ImportError:
        pass
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "" or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key != "" and key not in os.environ:
                os.environ[key] = value
    return True


def models():
    """The two model ids, after any override from the environment."""
    load_env()
    return {
        "small": os.environ.get("SOC_SMALL_MODEL") or DEFAULT_SMALL_MODEL,
        "strong": os.environ.get("SOC_STRONG_MODEL") or DEFAULT_STRONG_MODEL,
    }


def get_api_key():
    """Return the API key, or raise with a message that does not contain the key."""
    load_env()
    key = os.environ.get(API_KEY_ENV, "").strip()
    if key == "":
        raise RuntimeError(API_KEY_ENV + " is not set. Copy .env.example to .env and add your key, or export it in the shell.")
    return key


def describe():
    """Safe summary for logs and reports: model ids and whether a key is present, never the key."""
    load_env()
    return {"provider": PROVIDER, **models(), "temperature": TEMPERATURE, "max_output_tokens": MAX_OUTPUT_TOKENS,
            "api_key_present": os.environ.get(API_KEY_ENV, "").strip() != ""}


if __name__ == "__main__":
    print(describe())
