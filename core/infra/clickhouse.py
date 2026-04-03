import clickhouse_connect
from core.config import settings

_client = None


def get_client():
    global _client
    if _client is None:
        _client = clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            username=settings.clickhouse_user,
            password=settings.clickhouse_password,
        )
    return _client


async def fetch(query: str, **params) -> list[dict]:
    client = get_client()
    result = client.query(query, parameters=params)
    columns = result.column_names
    return [dict(zip(columns, row)) for row in result.result_rows]
