from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Category, Item, User

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

soccer = Category(name='Soccer')
session.add(soccer)

basketball = Category(name='Basketball')
session.add(basketball)

baseball = Category(name='Baseball')
session.add(baseball)

frisbee = Category(name='Frisbee')
session.add(frisbee)

snowboarding = Category(name='Snowboarding')
session.add(snowboarding)

rockClimbing = Category(name='Rock Climbing')
session.add(rockClimbing)

foosball = Category(name='Foosball')
session.add(foosball)

skating = Category(name='Skating')
session.add(skating)

hockey = Category(name='Hockey')
session.add(hockey)

session.commit()

print("Items added!")
