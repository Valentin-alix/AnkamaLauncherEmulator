import uuid


def generate_hash() -> str:
    return str(uuid.uuid4())
