# openai-python-httpx

Openai fork with ```APIRequestor``` class based on [HTTPX](https://www.python-httpx.org/). 
HTTPX provides a more modern and faster alternative to requests with additional features like HTTP2 support, HTTP 
connection pools etc.

## Installation

```bash
pip install .
```

Be careful, it will replace original openai package in your environment.

## Example of usage:

### Force initialization of HTTP connection pools for create methods
```python
import openai
openai.api_key = "sk-..."
openai.api_base = "https://api.openai.com"

openai.force_init_sync_pulls()

## Now you can use create methods with initialized HTTP connection pools
## or it will be initialized automatically after first call
## the same for acreate methods

response = openai.Completion.create(...)
```

### HTTPX with HTTP2 support
```python
import openai
openai.api_key = "sk-..."
openai.api_base = "https://api.openai.com"

openai.setup_custom_sync_session(http2=True)

## Now create methods will use HTTP2

response = openai.Completion.create(...)
```

[More examples](examples/httpx)
