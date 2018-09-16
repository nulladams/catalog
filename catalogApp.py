from flask import Flask, jsonify, request, url_for, redirect
from flask import abort, g, render_template
from sqlalchemy import create_engine
import random, string
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature,
                          SignatureExpired)
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
import requests
import httplib2
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User

app = Flask(__name__)

#Show catalof of categories and lasts items added
@app.route("/")
@app.route("/catalog")
def showCatalog():
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categories = session.query(Category).all()
    items = session.query(Item).all()
    engine.dispose()
    return render_template('catalog.html', categories=categories, items=items)

#Show items in a category
@app.route("/catalog/<int:category>/items")
def showItems(category_id):
    return category_id

#Add new items
@app.route("/catalog/items/new", methods=['GET','POST'])
def newItem():
    if request.method == 'POST':

        engine = create_engine('sqlite:///catalog.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        newItem = Item(title=request.form['title'],
                       description=request.form['description'],
                       cat_id=request.form['category'])
        print(newItem.title)
        print(newItem.description)
        print(newItem.cat_id)
        session.add(newItem)
        session.commit()
        engine.dispose()
        return redirect(url_for('showCatalog'))

    if request.method == 'GET':
        engine = create_engine('sqlite:///catalog.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        categories = session.query(Category).all()
        engine.dispose()
        return render_template('newitem.html', categories=categories)

#Show an item
@app.route("/catalog/<int:category_id>/items/<int:item_id>")
def showItem(category_id, item_id):
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    engine.dispose()
    # return "Show Item: %s, %s" % (category, item)
    return render_template('showitem.html', item=item)

#Edit an item
@app.route("/catalog/<int:item_id>/edit", methods=['GET','POST'])
def editItem(item_id):
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'GET':
        item = session.query(Item).filter_by(id=item_id).one()
        categories = session.query(Category).all()
        engine.dispose()
        return render_template('edititem.html',
                                item=item,
                                categories=categories)
    if request.method == 'POST':
        item = session.query(Item).filter_by(id=item_id).one()
        item.title = request.form['title']
        item.description = request.form['description']
        item.cat_id = request.form['category']
        session.add(item)
        session.commit()
        engine.dispose()
        return redirect(url_for('showCatalog'))

#Delete an item
@app.route("/catalog/<int:item_id>/delete", methods=['GET','POST'])
def deleteItem(item_id):
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'GET':
        engine.dispose()
        return render_template('deleteitem.html', item=item)
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        engine.dispose()
        #return "Delete Item: %s" % (item_id)
        return redirect(url_for('showCatalog'))

#Show login page
@app.route('/login')
def showLogin():
    return ("Login")

#Provide JSON endpoint for categories and items
@app.route("/catalog.json")
def showCatalogItems():
    return "JSON"


@app.route('/oauth/<provider>', methods = ['POST'])
def login(provider):
    print("ENTREI")
    if provider == 'google':

        print("entrei google")
        #print(request.json)
        print(request)
        print(request.data)
        #auth_code = request.json.get('auth_code')
        auth_code = request.data
        try:
            oauth_flow = flow_from_clientsecrets('g_client_secrets.json',scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the autorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return

        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
        print(answer)
        print(answer.json())
        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        engine = create_engine('sqlite:///catalog.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()

        engine.dispose()

        token = user.generate_auth_token(600)

        return jsonify({'token':token.decode('ascii')})

    else:
        return 'Unrecoginized Provider'



@app.route('/clientOAuth')
def showOAuthProviders():
    return render_template('clientOAuth.html')


#Start application
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
