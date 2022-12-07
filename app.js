//libraries and consts
const port = 8000;
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config();

const express = require('express');
const app = express();

var alert = require('alert');

var nodemailer = require('nodemailer');
var transport = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PW
    }
});

var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: false }));
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { ObjectId } = require('mongodb');
const algorithm = "aes-256-cbc";
const initVector = process.env.INIT_VEC;
const Securitykey = process.env.SEC_KEY;

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
  }
});

//signup or login process
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
          bcrypt.hash(req.body.pw, 10, function(err, hash) {
            let newUser = new User({
              fn: req.body.fn,
              ln: req.body.ln,
              mail: req.body.mail,
              pw: hash
            });
            res.render("inlogged", {gr: "Welcome, ", fn: req.body.fn, ln: req.body.ln});
            newUser.save(); 
            signed = true;
            cUser = req.body.mail;
          });
        }
    });
});

app.post('/login', (req, res, next) => {
    User.findOne({mail: req.body.lmail}, function(err, obj) {
        if(obj == null) {
          alert(`You need to sign up first!`);
          res.render("in");
        } else {
          bcrypt.compare(req.body.lpw, obj.pw, function(err, match) {
            if(match) {
              res.render("inlogged", {gr: "Hi once again, ", fn: obj.fn, ln: obj.ln});
              signed = true;
              cUser = obj.mail;
            } else {
              alert(`Wrong password!`);
              res.render("in");
            }
          })
        }
    });
});



//forgotten password
app.post('/forgotpass', (req, res, next) => {
    res.render("passforgot");
});

app.post('/newpass', (req, res, next) => {
  res.render("passforgot");
});

app.post('/sendemail', (req, res, next) => {
  User.findOne({mail: req.body.fmail}, function(err, obj) {
    if(obj==null) {
      alert(`There's no help for you if you don't even remember your mail address.`);
      res.render("passforgot");
    } else {
      let urlId = obj._id.valueOf();
      let urlTime = Date.now();

      var message = {
        from: process.env.MAIL_USER,
        to: req.body.fmail,
        subject: "Password database - reset your password",
        text: `Hello user. This is your key: http://localhost:8000/pass/${urlId}/${urlTime}`
      } 
      transport.sendMail(message, function(err, info) {
        if(err) {
            console.log(err);
        } else {
            res.render("passforgot");
            alert('Sent.');
        }
      })
    }
});
});


var difTime;
app.get('/pass/:id/:time', (req, res, next) => {
    let urlId2 = req.params.id;
    res.render("passnew");
    difTime = Date.now() - Number(req.params.time);
    
    app.post('/setnewpass', (req, res, next) => {
      if(difTime > 180000) {
        alert("Your link is not valid anymore.");
        res.render("passnew");
      } else if(req.body.npw != req.body.npwr) {
        alert("Passwords do not match.");
        res.render("passnew");
      } else {
        User.findOne({_id: ObjectId(urlId2)}, function(err, obj) {
          if(err) {
            alert("Your link is not valid.");
          } else {
            bcrypt.hash(req.body.npw, 10, function(err, hash) {
              User.updateOne({_id: ObjectId(urlId2)}, {pw: hash}, function(err, obj) {});
            });
            alert("New password set! Use it for logging in.");
            res.render("in");
          }
        });
      }
    })
});


//website pass schema
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


//logging out
app.post('/logout', (req, res, next) => {
  signed = false;
  res.render("in");
})


//one-password operations
app.post('/passadd', (req, res, next) => {
  if(signed) {
      const cipher = crypto.createCipheriv(algorithm, Securitykey, initVector);
      let encrPw = cipher.update(req.body.apw, "utf-8", "hex");
      encrPw += cipher.final("hex");
      let newPass = new Pass ({
        mail: cUser,
        wn: req.body.awn,
        pw: encrPw
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
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj.pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          alert(`Password for ${req.body.fwn} is ${decrPw}!`);
        }
    });
    res.render("inlogged", {gr: "Password database management", fn: "", ln: ""});
  }
});

app.post('/passupdate', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.uwn}, function(err, obj) {
      if(obj == null) {
        alert(`Password for ${req.body.uwn} not found!`);
      } else {
        alert(`Password for ${req.body.uwn} updated!`);
      }
    });
    const cipher = crypto.createCipheriv(algorithm, Securitykey, initVector);
    let encrPw = cipher.update(req.body.unpw, "utf-8", "hex");
    encrPw += cipher.final("hex");
    Pass.updateOne({mail: cUser, wn: req.body.uwn}, {pw: encrPw}, function(err, obj) {});
    res.render("inlogged", {gr: "Password database management", fn: "", ln: ""});
  }
});

app.post('/passdelete', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.dwn}, function(err, obj) {
      if(obj == null) {
        alert(`Password for ${req.body.dwn} not found!`);
      } else {
        alert(`Password for ${req.body.dwn} deleted!`);
      }
    });

    Pass.deleteOne({mail: cUser, wn: req.body.dwn}, function(err, obj) {});
    res.render("inlogged", {gr: "Password database management", fn: "", ln: ""});
  }
});



//table of passwords
app.post('/sapdef', (req, res, next) => {
  if(signed) {
    Pass.find({}, function(err, obj) {
      if(obj == null) {
        alert(`No passwords found!`);
      } else {
        let arr = [];
        for(let i = 0; i < obj.length; i++) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj[i].pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          arr.push([obj[i].wn, decrPw]);
        }
        res.render("table", arrx=arr);
      }
    });
  }
})

app.post('/sapsort1', (req, res, next) => {
  if(signed) {
    Pass.find({}, function(err, obj) {
      if(obj == null) {
        alert(`No passwords found!`);
      } else {
        let arr = [];
        for(let i = 0; i < obj.length; i++) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj[i].pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          arr.push([obj[i].wn, decrPw]);
        }
        arr.sort();
        res.render("table", arrx=arr);
      }
    });
  }
});

app.post('/sapsort2', (req, res, next) => {
  if(signed) {
    Pass.find({}, function(err, obj) {
      if(obj == null) {
        alert(`No passwords found!`);
      } else {
        let arr = [];
        for(let i = 0; i < obj.length; i++) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj[i].pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          arr.push([obj[i].wn, decrPw]);
        }
        arr.sort((a, b) => (a[1] > b[1] ? 1 : -1))
        res.render("table", arrx=arr);
      }
    });
  }
});


app.listen(port, function() {
    console.log(`Server running on port ${port}`);
})