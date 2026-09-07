from slowapi import Limiter
from slowapi.util import get_remote_address

# One Limiter for the whole app. Each router that needs rate limiting
# imports this same instance rather than constructing its own -- two
# separate Limiter() instances only one of which is registered as
# app.state.limiter is a real bug (the unregistered one's limits still
# apply, but its state isn't what the exception handler / any future
# introspection code expects to find).
limiter = Limiter(key_func=get_remote_address)
