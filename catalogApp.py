from flask import Flask, jsonify, request, url_for, redirect, flash
from flask import abort, g, render_template
from sqlalchemy import create_engine
import random
import string
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
import controller


# Google client secrets
CLIENT_ID = json.loads(open('g_client_secrets.json',
                            'r').read())['web']['client_id']


app = Flask(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username_or_token, password):
    user = controller.getUserByUsernameOrToken(username_or_token, password)
    if not user:
        return False
    g.user = user
    return True


# Show catalog with categories and lasts items added (start page)
@app.route("/")
@app.route("/catalog")
def showCatalog():
    categories = controller.getCategories()
    items = controller.getLastItems()
    category = ""
    return render_template('catalog.html', categories=categories,
                           items=items, category=category)


# Show catalog with categories and lasts items added, after looged in
@app.route("/catalogin")
def showCatalogIn():
    categories = controller.getCategories()
    items = controller.getLastItems()
    category = ""
    return render_template('catalogin.html', categories=categories,
                           items=items, category=category)


# Show items from a specific category
@app.route("/catalog/<int:category_id>/items")
def showItems(category_id):
    categories = controller.getCategories()
    items = controller.getItems(category_id)
    items_count = controller.countItems(category_id)
    category = controller.getCategory(category_id)
    category_name = category.name
    return render_template('catalog.html', categories=categories,
                           items=items, category=category_name,
                           count=items_count)


# Show items from a specific category after logged in
@app.route("/catalogin/<int:category_id>/items")
def showItemsIn(category_id):
    if ('username' in login_session):
        categories = controller.getCategories()
        items = controller.getItems(category_id)
        items_count = controller.countItems(category_id)
        category = controller.getCategory(category_id)
        category_name = category.name
        return render_template('catalogin.html', categories=categories,
                               items=items, category=category_name,
                               count=items_count)
    else:
        content = '''
        <script>
            function showAlert() {{
                alert('You do not have permission!Please login first!');
                window.location.href = "{catalog_url}";
            }}
        </script>
        <body onload='showAlert()'>
        '''
        alert = content.format(catalog_url=url_for('showCatalog'))
        return alert


# Add new items
@app.route("/catalogin/items/new", methods=['GET', 'POST'])
def newItem():
    if 'username' in login_session:
        if request.method == 'POST':
            item = controller.createItem(title=request.form['title'],
                                         description=request.form['description'],  # noqa
                                         cat_id=request.form['category'],
                                         user_id=login_session['user_id'])
            return redirect(url_for('showCatalogIn'))

        if request.method == 'GET':
            categories = controller.getCategories()
            return render_template('newitem.html', categories=categories)

    else:
        content = '''
        <script>
            function showAlert() {{
                alert('You do not have permission!Please login first!');
                window.location.href = "{catalog_url}";
            }}
        </script>
        <body onload='showAlert()'>
        '''
        alert = content.format(catalog_url=url_for('showCatalog'))
        return alert


# Show an item
@app.route("/catalog/<int:category_id>/items/<int:item_id>")
def showItem(category_id, item_id):
    item = controller.getItem(item_id)
    return render_template('showitem.html', item=item)


# Show item after logged in, with possibility to edit and detete the item
@app.route("/catalogin/<int:category_id>/items/<int:item_id>")
def showItemIn(category_id, item_id):
    if ('username' in login_session):
        isUserAuhorized = controller.checkUserAuthorization(login_session['user_id'],  # noqa
                                                            item_id)
        if isUserAuhorized:
            item = controller.getItem(item_id)
            return render_template('showitemin.html', item=item)
        else:
            content = '''
            <script>
                function showAlert() {{
                    alert('You do not have permission!Please login first!');
                    window.location.href = "{catalog_url}";
                }}
            </script>
            <body onload='showAlert()'>
            '''  # noqa
            alert = content.format(catalog_url=url_for('showCatalogIn'))
            return alert
    else:
        content = '''
        <script>
            function showAlert() {{
                alert('You do not have permission!Please login first!');
                window.location.href = "{catalog_url}";
            }}
        </script>
        <body onload='showAlert()'>
        '''
        alert = content.format(catalog_url=url_for('showCatalog'))
        return alert


# Edit an item
@app.route("/catalogin/<int:item_id>/edit", methods=['GET', 'POST'])
def editItem(item_id):
    if ('username' in login_session):
        isUserAuhorized = controller.checkUserAuthorization(login_session['user_id'],  # noqa
                                                            item_id)
        if isUserAuhorized:
            if request.method == 'GET':
                item = controller.getItem(item_id)
                categories = controller.getCategories()
                return render_template('edititem.html',
                                       item=item,
                                       categories=categories)
            if request.method == 'POST':
                item = controller.editItem(item_id=item_id,
                                           title=request.form['title'],
                                           description=request.form['description'],  # noqa
                                           cat_id=request.form['category'])  # noqa
                return redirect(url_for('showItemIn',
                                        category_id=item.cat_id,
                                        item_id=item.id))
        else:
            content = '''
            <script>
                function showAlert() {{
                    alert('You do not have permission!Please login first!');
                    window.location.href = "{catalog_url}";
                }}
            </script>
            <body onload='showAlert()'>
            '''  # noqa
            alert = content.format(catalog_url=url_for('showCatalogIn'))
            return alert

    else:
        content = '''
        <script>
            function showAlert() {{
                alert('You do not have permission!Please login first!');
                window.location.href = "{catalog_url}";
            }}
        </script>
        <body onload='showAlert()'>
        '''
        alert = content.format(catalog_url=url_for('showCatalog'))
        return alert


# Delete an item
@app.route("/catalogin/<int:item_id>/delete", methods=['GET', 'POST'])
def deleteItem(item_id):
    if ('username' in login_session):
        isUserAuhorized = controller.checkUserAuthorization(login_session['user_id'],  # noqa
                                                            item_id)
        if isUserAuhorized:
            if request.method == 'GET':
                item = controller.getItem(item_id)
                return render_template('deleteitem.html', item=item)
            if request.method == 'POST':
                controller.deleteItem(item_id)
                return redirect(url_for('showCatalogIn'))
        else:
            content = '''
            <script>
                function showAlert() {{
                    alert('You do not have permission!Please login first!');
                    window.location.href = "{catalog_url}";
                }}
            </script>
            <body onload='showAlert()'>
            '''  # noqa
            alert = content.format(catalog_url=url_for('showCatalogIn'))
            return alert

    else:
        content = '''
        <script>
            function showAlert() {{
                alert('You do not have permission!Please login first!');
                window.location.href = "{catalog_url}";
            }}
        </script>
        <body onload='showAlert()'>
        '''
        alert = content.format(catalog_url=url_for('showCatalog'))
        return alert


# Provide JSON endpoint for categories and items
@app.route("/catalog.json")
def showCatalogItems():
    if 'username' in login_session:
        categories = controller.getCategories()
        category_array = []
        for category in categories:
            category_dict = category.serialize
            items = controller.getItems(category.id)
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
        content = '''
        <script>
            function showAlert() {{
                alert('You do not have permission!Please login first!');
                window.location.href = "{catalog_url}";
            }}
        </script>
        <body onload='showAlert()'>
        '''
        alert = content.format(catalog_url=url_for('showCatalog'))
        return alert


# Provide JSON endpoint for a specific item
@app.route("/catalog/<int:item_id>/json")
def itemJSONendpoint(item_id):
    if ('username' in login_session):
        isUserAuhorized = controller.checkUserAuthorization(login_session['user_id'],  # noqa
                                                            item_id)
        if isUserAuhorized:
            item = controller.getItem(item_id)
            return jsonify(item=item.serialize)
        else:
            content = '''
            <script>
                function showAlert() {{
                    alert('You do not have permission!Please login first!');
                    window.location.href = "{catalog_url}";
                }}
            </script>
            <body onload='showAlert()'>
            '''  # noqa
            alert = content.format(catalog_url=url_for('showCatalogIn'))
            return alert
    else:
        content = '''
        <script>
            function showAlert() {{
                alert('You do not have permission!Please login first!');
                window.location.href = "{catalog_url}";
            }}
        </script>
        <body onload='showAlert()'>
        '''
        alert = content.format(catalog_url=url_for('showCatalog'))
        return alert


# Google sign-in
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Check if is the same user that asking to log in
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    # Exchange google local secrets with the client
    try:
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the ' +
                                            'authorization code.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Compare client local access_token with google oAuth service
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)  # noqa
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # Check for problems when authenticating
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']

    # Check if the id sent by the user
    # is the same id received by google oAuth service
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't " +
                                            "mach given user ID"), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # Check if the user that send request is the same the one
    # that has been authenticated on google
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does " +
                                            "not match"), 401)
        print("Token's client ID does not match app's")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    # Check if the user is already connected
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is ' +
                                            'already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Request user's infos to google oAuth server
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
    login_session['provider'] = 'google'

    # Check if the user is already in the database
    user = controller.getUserByEmail(email=login_session['email'])
    if not user:
        user = controller.createUser(username=login_session['username'],
                                     picture=login_session['picture'],
                                     email=login_session['email'])

    login_session['user_id'] = user.id
    token = user.generate_auth_token(600)
    login_session['credentials'] = token

    output = ''
    output += '<div><h3>Welcome, '
    output += login_session['username']
    output += '!</h3></div>'
    output += '<div style="width: 100%"><img src="'
    output += login_session['picture']
    output += '"style = "width: 100px; heigth: 100px; '
    output += 'border-radius: 150px; -webkit-border-radius: 150px; '
    output += '-moz-border-radius: 150px;"></div> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


# Show login page
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                                  string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Diconnect from google oAuth service
@app.route("/gdisconnect/")
def gdisconnect():
    access_token = login_session.get('access_token')
    # Check if user is connected
    if access_token is None:
        response = make_response(json.dumps('Current user ' +
                                            'not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Request disconnection for google oAuth server
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # Check if disconnection was performed
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully ' +
                                            'desconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token ' +
                                            'for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect user from local session
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
        return redirect(url_for('showCatalog'))
    else:
        flash("you were not logged in")
        return redirect(url_for('showCatalogIn'))


# Start application
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
