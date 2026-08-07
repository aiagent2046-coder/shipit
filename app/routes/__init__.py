"""Route modules extracted from app/main.py.

app/main.py was 4117 lines with 37 endpoints inline. Endpoints are being moved
here group by group, smallest and most isolated first, with the full test suite
run after each move.

Each module exposes a module-level ``router`` (a ``fastapi.APIRouter``) that
app/main.py includes. Routers declare full paths rather than using a
``prefix=``, so the URL of an endpoint stays greppable as a single string --
the same reason app/ops_endpoints.py does it that way.

Shared dependency providers live in ``dependencies.py``. Import them from
there, never redefine them: ``app.dependency_overrides`` keys on object
identity, and 29 test modules depend on those exact objects.
"""
