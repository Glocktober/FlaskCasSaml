#!/usr/bin/env python3
import os

from flask import Flask
from flask_session import Session
from FlaskSaml import FlaskSP
from FlaskCasSaml import CasBridge

from config import saml_config, session_config, cas_config

DEBUG = os.environ.get('DEBUG', False)

app = Flask(__name__)
app.config.from_mapping(session_config)
Session(app)

saml = FlaskSP(saml_config=saml_config,app=app)
cas = CasBridge(app, saml,config=cas_config)

if DEBUG:
    from flask import session

    @app.route('/sess')
    def sess():
        print(session)
        return {
            'username': session['username'],
            'attributes': session['attributes']
        }

