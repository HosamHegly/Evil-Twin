const express = require("express");
const Cors = require("cors");
const app = express();
const port = 8081;
app.use(express.json());
app.use(Cors());
// connect the app to the mysql database and create a table
console.log("Connecting to the database...");

const mysql = require("mysql");
const connection = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  port: 3306,
  password: "password",
});
// create a database with name fakeapi and a table with name accounts

connection.connect((err) => {
  if (err) {
    console.log("Error connecting to the database");
    console.log(err);
    return err;
  } else {
    console.log("connected");
  }
});

// create a database with name fakeapi
connection.query("CREATE DATABASE IF NOT EXISTS fakeapi", (err, result) => {
  if (err) {
    console.log("Error creating database");
    console.log(err);
    return err;
  }
  console.log("Database created");
});

// select the database
connection.query("USE fakeapi", (err, result) => {
  if (err) {
    console.log("Error selecting database");
    console.log(err);
    return err;
  }
  console.log("Database selected");
});
connection.query(
  "CREATE TABLE IF NOT EXISTS accounts (username VARCHAR(255), password VARCHAR(255))",
  (err, result) => {
    if (err) {
      console.log("Error creating table");
      console.log(err);
      return err;
    }
    console.log("Table created");
  }
);
// delete all null username and password with null password
connection.query(
  "DELETE FROM accounts WHERE password IS NULL",
  (err, result) => {
    if (err) {
      console.log("Error deleting null password");
      console.log(err);
      return err;
    }
    console.log("Null password deleted");
  }
);

// get a post request and push the username and password to the database
app.post("/accounts", (req, res) => {
  console.log(req.body);
  const { user, pass } = req.body;
  connection.query(
    "INSERT INTO accounts (username, password) VALUES (?, ?)",
    [user, pass],
    (err, result) => {
      if (err) {
        return err;
      } else {
        console.log("inserted");
      }
    }
  );
  res.status(200).send(JSON.stringify("Added account"));
});
// send all users and password in the database to client
app.get("/accounts", (req, res) => {
  connection.query("SELECT * FROM accounts", (err, result) => {
    if (err) {
      console.log("Error retrieving database");
      return err;
    }
    console.log(result);
    res.status(200).send(result);
  });
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
