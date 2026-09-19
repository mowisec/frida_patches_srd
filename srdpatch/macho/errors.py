"""What a finder raises.

The contract everywhere is EXACTLY ONE match. A pattern that matches twice is
as much a failure as one that matches nothing: it means the shape chosen does
not actually identify the site, and a patch written against it could land
anywhere. Both cases raise, and both stop the run.
"""


class NotFound(Exception):
    """A pattern matched nothing."""


class Ambiguous(Exception):
    """A pattern matched more than once, so it does not identify a site."""
