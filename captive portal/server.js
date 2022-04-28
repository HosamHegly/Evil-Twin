const express = require("express");
const Cors = require("cors");
const app = express();
const port = 8081;
app.use(express.json());
app.use(Cors());
// connect the app to the mysql database and create a table
const mysql = require("mysql");
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.NAME,
});
connection.connect((err) => {
  if (err) {
    return err;
  }
});
// create a table with accounts name
connection.query(
  "CREATE TABLE IF NOT EXISTS accounts (username VARCHAR(255), password INTEGER(255))",
  (err, result) => {
    if (err) {
      return err;
    }
  }
);
// get a post request and push the username and password to the database
app.post("/accounts", (req, res) => {
  const { username, password } = req.body;
  connection.query(
    "INSERT INTO accounts (username, password) VALUES (?, ?)",
    [username, password],
    (err, result) => {
      if (err) {
        return err;
      }
    }
  );
  res.status(200).send(JSON.stringify("Added account"));
});
// send all users and password in the database to client
app.get("/accounts", (req, res) => {
  connection.query("SELECT * FROM accounts", (err, result) => {
    if (err) {
      return err;
    }
    res.status(200).send(JSON.stringify("accounts", result));
  });
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
