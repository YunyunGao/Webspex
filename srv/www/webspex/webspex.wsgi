#!/usr/bin/env python3
# WEBSPEX MOD_CGI LOADING SCRIPT
# Revision 3
# Last Change: 2018-05-08
# Resources:
#   1) http://flask.pocoo.org/docs/0.12/deploying/mod_wsgi/
#   2) https://github.com/pypa/virtualenv/blob/master/virtualenv_embedded/activate_this.py

conda_path = '/home/auspex/miniconda3/'
webspex_path = '/srv/www/webspex/'
webspex_venv = webspex_path + 'envs/auspex'
webspex_vbin = webspex_venv + 'bin/'

#activate_this = webspex_venv + '/bin/activate_this.py'
#with open(activate_this) as file_:
#    exec(file_.read(), dict(__file__=activate_this))


# Enter python3 virtual environment containing Flask
import sys

#print(sys.version)

# change environment PATH variable
#old_os_path = os.environ.get('PATH', '')
#os.environ['PATH'] = os.path.dirname(webspex_vbin) + os.pathsep + old_os_path

# adjust site packages
#site.addsitedir(webspex_venv + 'lib/python3/site-packages/')

# adjust sys.prefix
#sys.prefix = webspex_venv

# Setup webspex directory as python import path
sys.path.insert(0, webspex_path)
#sys.path.append(webspex_venv + 'lib/python3/site-packages/')

# Import webspex as application
from webspex import app as application
