from sqlmodel import Session, create_engine

connect_args = {"check_same_thread": False}
engine = create_engine("sqlite:///orm-user.db", connect_args=connect_args)


def get_session():
    with Session(engine) as session:
        yield session
