# App "vibecoded" VULNERABLE A PROPÓSITO — solo para laboratorio. No desplegar.
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "clave-super-secreta"  # VULN: secreto hardcodeado


@app.route("/buscar")
def buscar():
    # VULN: SQL injection
    conn = sqlite3.connect("tienda.db")
    q = "SELECT * FROM productos WHERE nombre = '%s'" % request.args.get("q")
    return str(conn.execute(q).fetchall())


@app.route("/backup")
def backup():
    # VULN: command injection
    archivo = request.args.get("archivo")
    return subprocess.check_output("tar -czf /tmp/b.tgz " + archivo, shell=True)


@app.route("/config", methods=["POST"])
def config():
    # VULN: deserialización insegura
    return str(yaml.load(request.data, Loader=yaml.Loader))


@app.route("/sesion", methods=["POST"])
def sesion():
    # VULN: pickle con datos del usuario
    return str(pickle.loads(request.data))


if __name__ == "__main__":
    # VULN: debug activo y expuesto en todas las interfaces
    app.run(host="0.0.0.0", debug=True)
