 circuitbreaker 2.1.3

pip install circuitbreaker

Latest version

Released: Mar 31, 2025

Python Circuit Breaker pattern implementation
Navigation

    Project description
    Release history
    Download files

Verified details
These details have been verified by PyPI
Maintainers
Avatar for fabfuel from gravatar.com fabfuel
Unverified details
These details have not been verified by PyPI
Project links

    Homepage
    Download

Meta

    License: BSD License (BSD-3-Clause)
    Author: Fabian Fuelling

Classifiers

    Intended Audience
        Developers
    License
        OSI Approved :: BSD License
    Operating System
        MacOS
        POSIX
        Unix
    Programming Language
        Python
        Python :: 3.8
        Python :: 3.9
        Python :: 3.10

Report project as malware

Project description
CircuitBreaker
https://badge.fury.io/py/circuitbreaker.svg https://github.com/fabfuel/circuitbreaker/actions/workflows/build.yml/badge.svg

This is a Python implementation of the “Circuit Breaker” Pattern (https://martinfowler.com/bliki/CircuitBreaker.html). Inspired by Michael T. Nygard’s highly recommendable book Release It! (https://pragprog.com/titles/mnee2/release-it-second-edition/).
Installation

The project is available on PyPI. Simply run:

$ pip install circuitbreaker

Usage

This is the simplest example. Just decorate a function with the @circuit decorator:

from circuitbreaker import circuit

@circuit
def external_call():
    ...

Async functions are also supported:

@circuit
async def external_call():
    ...

This decorator sets up a circuit breaker with the default settings. The circuit breaker:

    monitors the function execution and counts failures

    resets the failure count after every successful execution (while it is closed)

    opens and prevents further executions after 5 subsequent failures

    switches to half-open and allows one test-execution after 30 seconds recovery timeout

    closes if the test-execution succeeded

    considers all raised exceptions (based on class Exception) as an expected failure

    is named “external_call” - the name of the function it decorates

What does failure mean?

A failure is a raised exception, which was not caught during the function call. By default, the circuit breaker listens for all exceptions based on the class Exception. That means, that all exceptions raised during the function call are considered as an “expected failure” and will increase the failure count.
Get specific about the expected failure

It is important, to be as specific as possible, when defining the expected exception. The main purpose of a circuit breaker is to protect your distributed system from a cascading failure. That means, you probably want to open the circuit breaker only, if the integration point on the other end is unavailable. So e.g. if there is an ConnectionError or a request Timeout.

If you are e.g. using the requests library (https://docs.python-requests.org/) for making HTTP calls, its RequestException class would be a great choice for the expected_exception parameter.

The logic for treating thrown exceptions as failures can also be customized by passing a callable. The callable will be passed the exception type and value, and should return True if the exception should be treated as a failure.

All recognized exceptions will be re-raised anyway, but the goal is, to let the circuit breaker only recognize those exceptions which are related to the communication to your integration point.

When it comes to monitoring (see Monitoring), it may lead to falsy conclusions, if a circuit breaker opened, due to a local OSError or KeyError, etc.
Configuration

The following configuration options can be adjusted via decorator parameters. For example:

from circuitbreaker import circuit

@circuit(failure_threshold=10, expected_exception=ConnectionError)
def external_call():
    ...

failure threshold

By default, the circuit breaker opens after 5 subsequent failures. You can adjust this value with the failure_threshold parameter.
recovery timeout

By default, the circuit breaker stays open for 30 seconds to allow the integration point to recover. You can adjust this value with the recovery_timeout parameter.
expected exception

By default, the circuit breaker listens for all exceptions which are based on the Exception class. You can adjust this with the expected_exception parameter. It can be either an exception class, an iterable of an exception classes, or a callable.

Use a callable if the logic to flag exceptions as failures is more complex than a type check. For example:

# Assume we are using the requests library
def is_not_http_error(thrown_type, thrown_value):
    return issubclass(thrown_type, RequestException) and not issubclass(thrown_type, HTTPError)

def is_rate_limited(thrown_type, thrown_value):
    return issubclass(thrown_type, HTTPError) and thrown_value.status_code == 429

@circuit(expected_exception=is_not_http_error)
def call_flaky_api(...):
    rsp = requests.get(...)
    rsp.raise_for_status()
    return rsp

@circuit(expected_exception=is_rate_limited)
def call_slow_server(...):
    rsp = requests.get(...)
    rsp.raise_for_status()
    return rsp

---

### Combining## Circuit Breaker + Retry Patterns

Combine circuit breaker and retry logic to maximize reliability and prevent cascading failures. Always place the circuit breaker before the retry decorator in your stack.

**CPU/IO Endpoint Example:**
```python
CopyInsert
decorated_func = trace_function(...)(job_logic)
decorated_func = track_errors(decorated_func)
decorated_func = measure_performance(...)(decorated_func)
decorated_func = circuit(failure_threshold=5, recovery_timeout=30)(decorated_func)
decorated_func = retry_decorator(max_retries=3)(decorated_func)
decorated_func = with_encrypted_parameters(decorated_func)
```

- `circuit` should wrap the function before `retry_decorator` to ensure retries are blocked when the circuit is open.
- Use for endpoints with expensive, error-prone, or external operations.

---

### Combining Circuit Breaker with Retry Logic

In production, you often want to retry failed calls before the circuit breaker opens. Use a retry decorator together with the circuit breaker:

```python
from circuitbreaker import circuit
from app.core.db_utils.decorators import retry_decorator  # Use your real retry decorator

@retry_decorator(max_retries=3, delay=2.0)
@circuit(failure_threshold=5, recovery_timeout=30, expected_exception=ConnectionError)
def call_external_api(...):
    rsp = requests.get(...)
    rsp.raise_for_status()
    return rsp
```

- The retry logic will attempt the call up to 3 times before letting the circuit breaker count a failure.
- This pattern maximizes resilience: transient errors are retried, but persistent failures open the circuit to prevent overload.
- Always put the retry decorator **above** the circuit breaker so retries happen before the circuit counts a failure.

---

By default, the circuit breaker name is the name of the function it decorates. You can adjust the name with parameter name.
fallback function

By default, the circuit breaker will raise a CircuitBreaker exception when the circuit is opened. You can instead specify a function to be called when the circuit is opened. This function can be specified with the fallback_function parameter and will be called with the same parameters as the decorated function would be.

The fallback type of call must also match the decorated function. For instance, if the decorated function is an async generator, the fallback_function must be an async generator as well.
Advanced Usage

If you apply circuit breakers to a couple of functions and you always set specific options other than the default values, you can extend the CircuitBreaker class and create your own circuit breaker subclass instead:

from circuitbreaker import CircuitBreaker

class MyCircuitBreaker(CircuitBreaker):
    FAILURE_THRESHOLD = 10
    RECOVERY_TIMEOUT = 60
    EXPECTED_EXCEPTION = RequestException

Now you have two options to apply your circuit breaker to a function. As an Object directly:

@MyCircuitBreaker()
def external_call():
    ...

Please note, that the circuit breaker class has to be initialized, you have to use a class instance as decorator (@MyCircuitBreaker()), not the class itself (@MyCircuitBreaker).

Or via the decorator proxy:

@circuit(cls=MyCircuitBreaker)
def external_call():
    ...

Monitoring

To keep track of the health of your application and the state of your circuit breakers, every circuit breaker registers itself at the CircuitBreakerMonitor. You can receive all registered circuit breakers via CircuitBreakerMonitor.get_circuits().

To get an aggregated health status, you can ask the Monitor via CircuitBreakerMonitor.all_closed(). Or you can retrieve the currently open circuits via CircuitBreakerMonitor.get_open() and the closed circuits via CircuitBreakerMonitor.get_closed().
