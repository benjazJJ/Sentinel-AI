from sentinela_core.db.base import Base, engine
from sentinela_core.db.models import Alert


def init_db():
    print("Creando tablas en MySQL...")
    Base.metadata.create_all(bind=engine)
    print("Tablas creadas correctamente")
