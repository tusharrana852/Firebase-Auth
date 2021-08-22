const express = require('express');
const app = express();
const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");

const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://fir-auth-d04af-default-rtdb.firebaseio.com"

  });
  

const csrfMiddleware = csrf({ cookie: true });

app.engine("html", require("ejs").renderFile);
app.use(express.static("static"));

app.use(bodyParser.OptionsJson);

app.use(cookieParser());
app.use(csrfMiddleware);


app.all("*", (req, res, next) => {
    res.cookie("XSRF-TOKEN", req.csrfToken());
    next();
  });
  
  app.get("/login", function (req, res) {
    res.render("login.html");
  });
  
  app.get("/signup", function (req, res) {
    res.render("signup.html");
  });
  
  app.get("/profile", function (req, res) {
    const sessionCookie = req.cookies.session || "";
  
    admin
      .auth()
      .verifySessionCookie(sessionCookie, true /** checkRevoked */)
      .then(() => {
        res.render("profile.html");
      })
      .catch((error) => {
        res.redirect("/login");
      });
  });

  app.get("/", function (req, res) {
    res.render("index.html");
  });

  
  app.post("/sessionLogin", (req, res) => {
    const idToken = req.body.idToken.toString();
  
    const expiresIn = 100 * 24 * 5 * 1000;
  
    admin
      .auth()
      .createSessionCookie(idToken, { expiresIn })
      .then(
        (sessionCookie) => {
          const options = { maxAge: expiresIn, httpOnly: true };
          res.cookie("session", sessionCookie, options);
          res.end(JSON.stringify({ status: "success" }));
        },
        (error) => {
          res.status(401).send("UNAUTHORIZED REQUEST!");
        }
      );
  });
  
  app.get("/sessionLogout", (req, res) => {
    res.clearCookie("session");
    res.redirect("/login");
  });

  


const port = 3000

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
  });

