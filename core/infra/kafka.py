from confluent_kafka import Consumer, Producer
from core.config import settings


def make_consumer(group_id: str, **kwargs) -> Consumer:
    config = {
        "bootstrap.servers": settings.kafka_bootstrap_servers,
        "group.id": group_id,
        "auto.offset.reset": "latest",
        "enable.auto.commit": False,
        **kwargs,
    }
    return Consumer(config)


def make_producer(**kwargs) -> Producer:
    config = {
        "bootstrap.servers": settings.kafka_bootstrap_servers,
        **kwargs,
    }
    return Producer(config)
