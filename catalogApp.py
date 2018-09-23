from flask import Flask, jsonify, request, url_for, redirect, flash
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
from flask import session as login_session
import json

CLIENT_ID = json.loads(open('g_client_secrets.json', 'r').read())['web']['client_id']

app = Flask(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username_or_token, password):
    print(username_or_token)
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    user_id = User.verify_auth_token(username_or_token)
    print('user id:' + str(user_id))

    if user_id:
        #user = session.query(User).filter_by(username=username).first()
        user = session.query(User).filter_by(id = user_id).one()
        print(user)
    else:
        user = session.query(User).filter_by(username=username_or_token).first()
        print(user)
        if not user:
            print("User not found")
            return False
        elif not user.verify_password(password):
            print("Unable to verify password")
            return False

    engine.dispose()

    g.user=user
    return True


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


@app.route("/catalogin")
def showCatalogIn():
    if 'username' in login_session:
        engine = create_engine('sqlite:///catalog.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        categories = session.query(Category).all()
        items = session.query(Item).all()
        engine.dispose()
        return render_template('catalogin.html', categories=categories, items=items)
    else:
        return '''<script>
                    function showAlert() {
                        alert('You do not have permission! Please login first!');
                        window.location.href = "''' + url_for('showCatalog') + '''";
                    }
                  </script>
                  <body onload='showAlert()'>'''

#Show items in a category
@app.route("/catalog/<int:category>/items")
def showItems(category_id):
    return category_id

#Add new items
@app.route("/catalogin/items/new", methods=['GET','POST'])
def newItem():
    if 'username' in login_session:
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
            return redirect(url_for('showCatalogIn'))

        if request.method == 'GET':
            engine = create_engine('sqlite:///catalog.db')
            Base.metadata.bind = engine
            DBSession = sessionmaker(bind=engine)
            session = DBSession()
            categories = session.query(Category).all()
            engine.dispose()
            return render_template('newitem.html', categories=categories)

    else:
        return '''<script>
                    function showAlert() {
                        alert('You do not have permission! Please login first!');
                        window.location.href = "''' + url_for('showCatalog') + '''";
                    }
                  </script>
                  <body onload='showAlert()'>'''

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

@app.route("/catalogin/<int:category_id>/items/<int:item_id>")
def showItemIn(category_id, item_id):
    if 'username' in login_session:
        engine = create_engine('sqlite:///catalog.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        item = session.query(Item).filter_by(id=item_id).one()
        engine.dispose()
        # return "Show Item: %s, %s" % (category, item)
        return render_template('showitemin.html', item=item)
    else:
        return '''<script>
                    function showAlert() {
                        alert('You do not have permission! Please login first!');
                        window.location.href = "''' + url_for('showCatalog') + '''";
                    }
                  </script>
                  <body onload='showAlert()'>'''

#Edit an item
@app.route("/catalogin/<int:item_id>/edit", methods=['GET','POST'])
def editItem(item_id):
    if 'username' in login_session:
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
            return redirect(url_for('showCatalogIn'))
    else:
        return '''<script>
                    function showAlert() {
                        alert('You do not have permission! Please login first!');
                        window.location.href = "''' + url_for('showCatalog') + '''";
                    }
                  </script>
                  <body onload='showAlert()'>'''

#Delete an item
@app.route("/catalogin/<int:item_id>/delete", methods=['GET','POST'])
def deleteItem(item_id):
    if 'username' in login_session:
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
            return redirect(url_for('showCatalogIn'))
    else:
        return '''<script>
                    function showAlert() {
                        alert('You do not have permission! Please login first!');
                        window.location.href = "''' + url_for('showCatalog') + '''";
                    }
                  </script>
                  <body onload='showAlert()'>'''


#Provide JSON endpoint for categories and items
@app.route("/catalog.json")
def showCatalogItems():
    if 'username' in login_session:
        engine = create_engine('sqlite:///catalog.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        categories = session.query(Category).all()
        category_array = []
        for category in categories:
            category_dict = category.serialize
            items = session.query(Item).filter_by(id=category.id).all()
            item_array = []
            for item in items:
                item_array.append(item.serialize)
            item_dict = {}
            category_dict['items'] = item_array
            category_array.append(category_dict)
        catalog = {}
        catalog['categories'] = category_array
        return jsonify(catalog)
    else:
        return '''<script>
                    function showAlert() {
                        alert('You do not have permission! Please login first!');
                        window.location.href = "''' + url_for('showCatalog') + '''";
                    }
                  </script>
                  <body onload='showAlert()'>'''




'''
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

        print(name)

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
        login_session['username_or_token'] = token

        return jsonify({'token':token.decode('ascii')})

    else:
        return 'Unrecoginized Provider'


#Show oAuth login page
@app.route('/clientOAuth')
def showOAuthProviders():
    return render_template('clientOAuth.html')
'''

@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    print("code")
    print(code)

    try:
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    print("access token")
    print(access_token)
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    print("result")
    print(result)

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't mach given user ID"), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match"), 401)
        print("Token's client ID does not match app's")
        response.headers['Content-Type'] = 'application/json'
        return response

    #stored_credentials = login_session.get('credentials')
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    #if stored_credential is not None and gplus_id == stored_gplus_id:
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt':'json'}
    answer = requests.get(userinfo_url, params=params)

    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
    login_session['provider'] = 'google'

    #Check if the user is already in the database
    print("email: " + login_session['email'])
    #user_id = webserverdb.get_UserID(login_session['email'])
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    user = session.query(User).filter_by(email=login_session['email']).first()
    print("user id: " + str(user.id))
    # if user_id == None: # if not user_id:
    if not user:
        print("Entrei user ID")
        #user_id = createUser(login_session)
        user = User(username=login_session['username'], picture=login_session['picture'], email=login_session['email'])
        session.add(user)
        session.commit()
    engine.dispose()

    login_session['user_id'] = user.id
    token = user.generate_auth_token(600)
    login_session['credentials'] = token
    print('SHOWING LOGIN SESSION')
    print(login_session)

    output = ''
    output +='<div><h3>Welcome, '
    output += login_session['username']

    output += '!</h3></div>'
    output += '<div style="width: 100%"><img src="'
    output += login_session['picture']
    output += '"style = "width: 100px; heigth: 100px; border-radius: 150px; -webkit-border-radius: 150px; -moz-border-radius: 150px;"></div> '
    flash("you are now logged in as %s"%login_session['username'])
    print("done!")
    return output


#Show login page
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state']=state
    #return "The current sesion state is %s" %login_session['state']
    return render_template('login.html', STATE=state)


@app.route("/gdisconnect/")
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    #access_token = credentials.get('access_token')
    print("In gdisconnect access token is %s" % access_token)
    print("User name is: ")
    print(login_session['username'])
    print("login_session['access_token']: ")
    print(login_session['access_token'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    print("url: ")
    print(url)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print("result is ")
    print(result)

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully desconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        del login_session['credentials']
        print(login_session)
        flash("You have Successfully been logged out.")
        print("You have Successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("you were not logged in")
        print("you were not logged in")
        return redirect(url_for('showCatalogIn'))


#Start application
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.static_folder = 'static'
    app.run(host='0.0.0.0', port=8000)
