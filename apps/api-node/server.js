// App "vibecoded" VULNERABLE A PROPÓSITO — solo para laboratorio. No desplegar.
const express = require('express');
const mysql = require('mysql');
const _ = require('lodash');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// VULN: credenciales hardcodeadas
const db = mysql.createConnection({
  host: 'db.lab.local',
  user: 'admin',
  password: 'SuperSecreta123!',
  database: 'tienda'
});

// VULN: SQL injection (concatenación de entrada del usuario)
app.get('/api/users', (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(q, (err, rows) => res.json(rows));
});

// VULN: command injection
app.get('/api/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

// VULN: prototype pollution con lodash antiguo
app.post('/api/settings', (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

// VULN: XSS reflejado
app.get('/hola', (req, res) => {
  res.send('<h1>Hola ' + req.query.nombre + '</h1>');
});

app.listen(3000);
