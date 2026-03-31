"""
Consumer lag health check for dp-security-eval.

Exits 0 if all partitions are within the lag threshold.
Exits 1 if any partition exceeds the threshold or Kafka is unreachable.

Usage:
    uv run python scripts/health_check.py [--max-lag 5000]
"""
import argparse
import sys

from confluent_kafka import Consumer, KafkaException
from confluent_kafka.admin import AdminClient

from core.config import settings

DEFAULT_MAX_LAG = 10_000  # events per partition before we flag unhealthy


def check_consumer_lag(group_id: str, topic: str, max_lag: int) -> bool:
    admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers})

    try:
        # Fetch committed offsets for the consumer group
        consumer = Consumer({
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "group.id": group_id,
        })
        metadata = consumer.list_topics(topic, timeout=10)
        if topic not in metadata.topics:
            print(f"ERROR: topic {topic!r} not found", file=sys.stderr)
            consumer.close()
            return False

        partitions = [
            __import__("confluent_kafka").TopicPartition(topic, p)
            for p in metadata.topics[topic].partitions
        ]

        committed = consumer.committed(partitions, timeout=10)
        consumer.assign(partitions)
        end_offsets = consumer.get_watermark_offsets  # not available on plain Consumer

        # Use low-level AdminClient to get end offsets
        consumer.close()

        # Re-approach: use a temporary consumer to get high watermarks
        tmp = Consumer({
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "group.id": f"{group_id}-healthcheck",
            "auto.offset.reset": "latest",
        })
        tmp.assign(partitions)

        total_lag = 0
        worst_partition = None
        worst_lag = 0

        for tp in committed:
            committed_offset = tp.offset if tp.offset >= 0 else 0
            low, high = tmp.get_watermark_offsets(tp, timeout=5)
            lag = max(0, high - committed_offset)
            total_lag += lag
            if lag > worst_lag:
                worst_lag = lag
                worst_partition = tp.partition

        tmp.close()

        status = "OK" if worst_lag <= max_lag else "WARN"
        print(
            f"group={group_id} topic={topic} "
            f"total_lag={total_lag} worst_partition={worst_partition} "
            f"worst_lag={worst_lag} max_lag={max_lag} status={status}"
        )
        return worst_lag <= max_lag

    except KafkaException as exc:
        print(f"ERROR: Kafka unreachable — {exc}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="dp-security-eval consumer lag check")
    parser.add_argument(
        "--max-lag",
        type=int,
        default=DEFAULT_MAX_LAG,
        help=f"Max acceptable lag per partition (default {DEFAULT_MAX_LAG})",
    )
    args = parser.parse_args()

    healthy = check_consumer_lag(
        group_id="dp-security-eval",
        topic=settings.kafka_events_topic,
        max_lag=args.max_lag,
    )
    sys.exit(0 if healthy else 1)


if __name__ == "__main__":
    main()
