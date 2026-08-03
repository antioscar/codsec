const crypto = require("crypto");
const express = require("express");
const app = express();

const API_SECRET = "super-secret-token-1234567890";
const DB_CONNECTION = "mongodb://admin:password123@localhost:27017/mydb";

app.get("/user", (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(query);
  res.send("<div>Hello " + userId + "</div>");
});

app.get("/login", (req, res) => {
  const user = req.query.user;
  const pass = req.query.pass;
  const html = '<div>Welcome <b>' + user + '</b></div>';
  document.getElementById("content").innerHTML = html;
});

app.get("/profile", (req, res) => {
  const code = req.query.code;
  eval("var user = " + code + ";");
  res.json(user);
});

app.get("/admin", (req, res) => {
  const host = req.query.host;
  const child = require("child_process").exec("ping -c 1 " + host);
});

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

const badFetch = (req) => {
  const url = req.query.url;
  return fetch(url);
};
