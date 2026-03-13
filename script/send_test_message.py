"""向 RabbitMQ 发送一条测试扫描消息。

用法:
    python scripts/send_test_message.py
    python scripts/send_test_message.py --config /path/to/config.yaml
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
import pika
import yaml
from botocore.config import Config
from pymongo import MongoClient

SCRIPT_DIR = Path(__file__).parent
DEFAULT_CONFIG = SCRIPT_DIR.parent / "config.yaml"

# OSS (S3 兼容) 配置 —— 用于动态生成预签名下载链接
OSS_ENDPOINT = "https://oss-yg-cztt.yun.qianxin-inc.cn:443"
OSS_AK = "MW18ELCSL784BBJX57VG"
OSS_SK = "w2LAxJUOdlT3RsvbrFBmDFYJJuRDiYVaBGeCoqLY"
OSS_BUCKET = "skills-scan"
OSS_KEY = "malicious-exfiltrator.zip"
OSS_URL_EXPIRES = 7200  # 预签名链接有效期（秒）


def _s3_client():
    return boto3.client(
        "s3",
        endpoint_url=OSS_ENDPOINT,
        aws_access_key_id=OSS_AK,
        aws_secret_access_key=OSS_SK,
        config=Config(signature_version="s3v4"),
        region_name="default",
    )


def upload_and_get_presigned_url(local_path: str) -> str:
    """上传本地文件到 OSS test/ 路径下，并返回预签名下载链接。"""
    s3 = _s3_client()
    filename = Path(local_path).name
    key = f"test/{filename}"
    print(f"上传本地文件: {local_path} -> s3://{OSS_BUCKET}/{key}")
    s3.upload_file(local_path, OSS_BUCKET, key)
    print("上传完成")
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": OSS_BUCKET, "Key": key},
        ExpiresIn=OSS_URL_EXPIRES,
    )


def generate_presigned_url(key: str = OSS_KEY) -> str:
    """使用 boto3 生成 S3 兼容的预签名下载链接。"""
    s3 = _s3_client()
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": OSS_BUCKET, "Key": key},
        ExpiresIn=OSS_URL_EXPIRES,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="发送测试扫描消息到 RabbitMQ")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="配置文件路径")
    parser.add_argument("--url", default=None, help="技能包下载链接（不指定则自动生成预签名链接）")
    parser.add_argument("--file", default=None, help="本地技能包文件路径，自动上传到 OSS test/ 目录后生成链接")
    parser.add_argument("--priority", type=int, default=5, help="任务优先级 (默认 5)")
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    rmq = cfg["rabbitmq"]
    mongo_cfg = cfg["mongodb"]

    if args.file:
        download_url = upload_and_get_presigned_url(args.file)
    elif args.url:
        download_url = args.url
    else:
        download_url = generate_presigned_url()
    print(f"下载链接: {download_url}")

    task_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    message = {
        "task_id": task_id,
        "skill_download_url": download_url,
        "scan_options": {
            "policy": "balanced",
            "enable_llm": True,
            "enable_qax_ti": True,
        },
        "priority": args.priority,
        "enqueue_time": now,
    }

    # Step 1: 在 MongoDB 中创建 pending 状态的 task 记录
    client = MongoClient(mongo_cfg.get("uri", "mongodb://localhost:27017"))
    db = client[mongo_cfg.get("database", "qax_skill_scan")]
    tasks_col = db[mongo_cfg.get("tasks_collection", "tasks")]
    task_doc = {
        "task_id": task_id,
        "status": "pending",
        "created_at": now,
        "skill_download_url": download_url,
        "priority": args.priority,
    }
    tasks_col.insert_one(task_doc)
    client.close()
    print(f"MongoDB task 记录已创建 (status=pending)")

    # Step 2: 向 RabbitMQ 发送扫描消息
    credentials = pika.PlainCredentials(rmq["username"], rmq["password"])
    params = pika.ConnectionParameters(
        host=rmq["host"],
        port=rmq["port"],
        virtual_host=rmq["vhost"],
        credentials=credentials,
    )

    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=rmq["queue_name"], durable=True)
    channel.basic_publish(
        exchange="",
        routing_key=rmq["queue_name"],
        body=json.dumps(message),
        properties=pika.BasicProperties(
            delivery_mode=2,
            content_type="application/json",
        ),
    )
    connection.close()

    print(f"MQ 消息已发送 -> queue={rmq['queue_name']}, task_id={task_id}")
    print(json.dumps(message, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

