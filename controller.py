from sqlalchemy import create_engine
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def getUserByUsernameOrToken(username_or_token):
    user_id = User.verify_auth_token(username_or_token)
    user = None
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(username=username_or_token).first()  # noqa
        if not user:
            return None
        elif not user.verify_password(password):
            print("Unable to verify password")
            return None
    return user


def getUserByEmail(email):
    return session.query(User).filter_by(email=email).first()  # noqa


def getUser(user_id):
    return session.query(User).filter_by(user_id=user_id).first()  # noqa


def getCategories():
    return session.query(Category).all()


def createUser(username, picture, email):
    newUser = User(username=username,
                   picture=picture,
                   email=email)
    session.add(newUser)
    session.commit()
    return newUser


def getCategory(cat_id):
    return session.query(Category).filter_by(id=cat_id).one()


def getLastItems():
    return session.query(Item).order_by(Item.id.desc()).limit(5)


def getItem(item_id):
    return session.query(Item).filter_by(id=item_id).one()


def getItems(cat_id):
    return session.query(Item).filter_by(cat_id=cat_id).all()


def countItems(cat_id):
    return session.query(Item).filter_by(cat_id=cat_id).count()


def createItem(title, description, cat_id, user_id):
    item = Item(title=title,
                description=description,
                cat_id=cat_id,
                user_id=user_id)
    session.add(item)
    session.commit()
    return item


def editItem(item_id, title, description, cat_id):
    item = session.query(Item).filter_by(id=item_id).one()
    item.title = title
    item.description = description
    item.cat_id = cat_id
    session.add(item)
    session.commit()
    return item


def deleteItem(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    session.delete(item)
    session.commit()
    return


def checkUserAuthorization(login_user_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    if item.user_id == login_user_id:
        return True
    else:
        return False
