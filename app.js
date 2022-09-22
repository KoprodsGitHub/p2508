//libraries and consts
const port = 8000;
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config();

const express = require('express');
const app = express();

var alert = require('alert');

var bodyParser = require('body-parser')
app.use(bodyParser.urlencoded({ extended: false }));

app.set("view engine", "pug");

//database connection
const url = process.env.DB_URL;
const connectionParams={
    useNewUrlParser: true,
    useUnifiedTopology: true 
}

mongoose.connect(url,connectionParams).then(() => {
    console.log('Connected to the database ')
})
.catch( (err) => {
 console.error(`Error connecting to the database. n${err}`);
})

//mongoose schema
const UserSchema = new mongoose.Schema({
  fn: {
    type: String,
    required: true,
  },
  ln: {
    type: String,
    required: true,
  },
  mail: {
    type: String,
    required: true,
  },
  pw: {
    type: String,
    required: true,
  },
  pwr: {
    type: String,
    required: true,
  },
});

//process
const User = mongoose.model("User", UserSchema);
var signed = false;
var cUser = "";

app.get('/', function(req, res) {
    res.render("in");
});

app.post('/signup', (req, res, next) => {
    User.findOne({mail: req.body.mail}, function(err, obj) {
        if(req.body.pw != req.body.pwr) {
          alert(`Passwords do not match!`);
          res.render("in");
        } else if(obj != null) {
          alert(`Account with this e-mail has already been created!`);
          res.render("in");
        } else if(obj == null) {
          let newUser = new User({
            fn: req.body.fn,
            ln: req.body.ln,
            mail: req.body.mail,
            pw: req.body.pw,
            pwr: req.body.pwr
          });
          res.render("inlogged", {gr: "Welcome, ", fn: req.body.fn, ln: req.body.ln});
          newUser.save();
          signed = true;
          cUser = obj.mail;
        }
    });
});

app.post('/login', (req, res, next) => {
    User.findOne({mail: req.body.lmail}, function(err, obj) {
        if(obj == null) {
          alert(`You need to sign up first!`);
          res.render("in");
        } else if(obj.pw != req.body.lpw) {
          alert(`Wrong password!`);
          res.render("in");
        } else {
          res.render("inlogged", {gr: "Hi once again, ", fn: obj.fn, ln: obj.ln});
          signed = true;
          cUser = obj.mail;
        }
    });
});

//mongoose schema
const PassSchema = new mongoose.Schema({
  mail: {
    type: String,
    required: true,
  },
  wn: {
    type: String,
    required: true,
  },
  pw: {
    type: String,
    required: true,
  }
});

const Pass = mongoose.model("Pass", PassSchema);

app.post('/passadd', (req, res, next) => {
  if(signed) {
      let newPass = new Pass ({
        mail: cUser,
        wn: req.body.awn,
        pw: req.body.apw
      });
      newPass.save();
      alert(`Password for ${req.body.awn} added!`);
      res.render("inlogged", {gr: "Password database management", fn: "", ln: ""});
  }
});

app.post('/passfind', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.fwn}, function(err, obj) {
        if(obj == null) {
          alert(`Password for ${req.body.fwn} not found!`);
        } else {
          alert(`Password for ${req.body.fwn} is ${obj.pw}!`);
        }
    });
    res.render("inlogged", {gr: "Password database management", fn: "", ln: ""});
  }
});

app.post('/passupdate', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.uwn, pw: req.body.uopw}, function(err, obj) {
      if(obj == null) {
        alert(`Password for ${req.body.uwn} not found!`);
      } else {
        alert(`Password for ${req.body.uwn} updated!`);
      }
    });

    Pass.updateOne({mail: cUser, wn: req.body.uwn, pw: req.body.uopw}, {pw: req.body.unpw}, function(err, obj) {});
    res.render("inlogged", {gr: "Password database management", fn: "", ln: ""});
  }
});

app.post('/passdelete', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.dwn, pw: req.body.dpw}, function(err, obj) {
      if(obj == null) {
        alert(`Wrong password for ${req.body.dwn}!`);
      } else {
        alert(`Password for ${req.body.dwn} deleted!`);
      }
    });

    Pass.deleteOne({mail: cUser, wn: req.body.dwn, pw: req.body.dpw}, function(err, obj) {});
    res.render("inlogged", {gr: "Password database management", fn: "", ln: ""});
  }
});

app.listen(port, function() {
    console.log(`Server running on port ${port}`);
})