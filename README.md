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

### Force HTTP connection pools initialization for openai create methods
```python
import openai
openai.api_key = "sk-..."

openai.force_init_sync_pulls()

## Now you can use create methods with initialized HTTP connection pools
## or it will be initialized automatically after first call
## the same for acreate methods

response = openai.Completion.create(...)
```

### Setup HTTP2 support for openai create methods
```python
import openai
openai.api_key = "sk-..."

openai.setup_custom_sync_session(http2=True)

## Now create methods will use HTTP2

response = openai.Completion.create(...)
```

[More examples](examples/httpx)


### Measurements

```python
import time
import openai
openai.api_key = "sk-..."

without_pulls_delay, with_pulls_delay = [], []

for _ in range(10):
    start = time.time()
    openai.ChatCompletion.create(
        model="gpt-3.5-turbo", messages=[{"role": "user", "content": "Test message. Ignore it."}], temperature=0.0,
    )
    without_pulls_delay.append(time.time() - start)
    openai.reset_sessions()

for _ in range(10):
    openai.force_init_sync_pulls()
    start = time.time()
    openai.ChatCompletion.create(
        model="gpt-3.5-turbo", messages=[{"role": "user", "content": "Test message. Ignore it."}], temperature=0.0,
    )
    with_pulls_delay.append(time.time() - start)
    openai.reset_sessions()

print(f"Average time without pulls: {sum(without_pulls_delay) / len(without_pulls_delay)}")
print(f"Average time with pulls: {sum(with_pulls_delay) / len(with_pulls_delay)}")

# Average time without pulls: 1.2538371324539184
# Average time with pulls: 0.9621359586715699
```

[Comparison with openai](https://colab.research.google.com/drive/1zds0HIqBZeVcvJDv0Gj2bzKyx3mX0d3M?usp=sharing)
