from flask import Flask, jsonify, request, url_for, abort, g, render_template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
import random, string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from flask_httpauth import HTTPBasicAuth

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
import requests
import httplib2


app = Flask(__name__)

@app.route("/")
def showCatalog():
    return "Catalog"

@app.route("/catalog/<category>/items")
def showItems(category):
    return category

@app.route("/catalog/items/new")
def newItem():
    return "New Item"


@app.route("/catalog/<category>/items/<item>")
def showItem(category, item):
    return "Show Item: %s, %s" % (category, item)

@app.route("/catalog/<item>/edit")
def editItem(item):
    return "Edit Item: %s" % (item)

@app.route("/catalog/<item>/delete")
def deleteItem(item):
    return "Delete Item: %s" % (item)

@app.route("/login")
def showLogin():
    return ("Login")

@app.route("/catalog.json")
def showCatalogItems():
    return "JSON"



if __name__ == '__main__':
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=8000)
