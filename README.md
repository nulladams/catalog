# Item Catalog

Item Catalog is a web application to store items according to sports categories. To create, edit and delete items, authentication and authorization are needed. When logged into the app is also possible to access an API endpoint with all categories and items registered in the database. The authentication is made through the google oAuth service.

# Requirements
The application was developed using Python3 and Flask framework, sqlite3 database, sqlalchemy library for database handling, and oauth2client library for google oauth service authentication. In case of executing locally, make sure to have them installed.
Follow the instructions bellow to have the environment ready.

- For Windows users, please install [Git Bash](https://git-scm.com/downloads) to have a Unix-style terminal.
- Install the virtual machine [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (platform package)
- Install [Vangrant](https://www.vagrantup.com/downloads.html) software
- Log in on Github and fork the [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm) repository to have Vagrant configuration file
- Clone vagrant repository to your local machine
```sh
$git clone http://github.com/<username>/fullstack-nanodegree-vm fullstack
```
- Run the virtual machine
```sh
$cd fullstack
$vagrant up
$vagrant ssh
$cd /vagrant
```
The `/vagrant` directory is where the files will be shared with the local machine
- Log in on Github and fork the _Item Catalog_ repository
- Clone the repository to your local machine
```sh
$git clone http://github.com/<username>/catalog catalog
$cd catalog
```
- Execute first time the catalogApp to create the _catalog.db_ database file
```sh
$python3 catalogApp.py
```
- After, run the _loadCategories.py_ to insert categories into the database
```sh
$python3 loadCategories.py
```


# Running
1) Run catalogApp.py file
```sh
$python3 catalogApp.py
```

2) Open a web browser and type the address "http://localhost:8000":

3) To access the API endpoint, type the address "http://localhost:8000/catalog.json";

# License
[MIT](https://choosealicense.com/licenses/mit/)
