from sqlalchemy import create_engine, text
import config, os
if config.USE_AWS and all([config.RDS_HOST, config.RDS_USER]):
    URI = f"mysql+pymysql://{config.RDS_USER}:{config.RDS_PASSWORD}" \
          f"@{config.RDS_HOST}/{config.RDS_DB}"
    engine = create_engine(URI, pool_recycle=280, echo=False)
else:
    engine = None        # 로컬 SQLite 그대로 사용
