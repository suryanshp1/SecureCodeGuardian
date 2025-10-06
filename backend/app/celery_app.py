from celery import Celery

# Single Celery instance exported as `celery`
celery = Celery(
    'codeguardian',
    broker='redis://redis:6379/0',
    backend='redis://redis:6379/0',
)

# Basic configuration
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
)

# Let Celery autodiscover tasks from the `app` package
celery.autodiscover_tasks(['app'])