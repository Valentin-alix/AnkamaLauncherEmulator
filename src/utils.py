import uuid


def generate_random_hash() -> str:
    return str(uuid.uuid4())
