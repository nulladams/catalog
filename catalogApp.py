from flask import Flask, jsonify, request, url_for
from flask import abort, g, render_template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
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



app = Flask(__name__)

#Show catalof of categories and lasts items added
@app.route("/")
def showCatalog():
    return "Catalog"

#Show items in a category
@app.route("/catalog/<category>/items")
def showItems(category):
    return category

#Add new items
@app.route("/catalog/items/new")
def newItem():
    return "New Item"

#Show an item
@app.route("/catalog/<category>/items/<item>")
def showItem(category, item):
    return "Show Item: %s, %s" % (category, item)

#Edit an item
@app.route("/catalog/<item>/edit")
def editItem(item):
    return "Edit Item: %s" % (item)

#Delete an item
@app.route("/catalog/<item>/delete")
def deleteItem(item):
    return "Delete Item: %s" % (item)

#Show login page
@app.route("/login")
def showLogin():
    return ("Login")

#Provide JSON endpoint for categories and items
@app.route("/catalog.json")
def showCatalogItems():
    return "JSON"


#Start application
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
