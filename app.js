//libraries and consts
const port = 8000;
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config();

const express = require('express');
const app = express();
const session = require("express-session");
const cookieParser = require("cookie-parser");
app.use(cookieParser());
app.use(session({
    secret: process.env.SECRET,
    saveUninitialized: true,
    resave: true
}));

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
    res.render("in", {h: true, fn: "Hi"});
});

app.post('/signup', (req, res, next) => {
    if(req.body.fn == "" || req.body.ln == "" || req.body.mail == "" || req.body.pw == "" || req.body.pwr == "") {
      res.render("in", {h: false, fn: `When signing up, need to fill all of the fields.`});
    } else {
      User.findOne({mail: req.body.mail}, function(err, obj) {
          if(req.body.pw != req.body.pwr) {
            res.render("in", {h: false, fn: `Passwords do not match!`});
          } else if(obj != null) {
            res.render("in", {h: false, fn: `Account with this e-mail has already been created!`});
          } else if(obj == null) {
            bcrypt.hash(req.body.pw, 10, function(err, hash) {
              let newUser = new User({
                fn: req.body.fn,
                ln: req.body.ln,
                mail: req.body.mail,
                pw: hash
              });
              res.render("inlogged", {gr: "Password database management", h: true, fn: "", ln: ""});
              newUser.save(); 
              req.session.user = newUser;
              req.session.save();
              signed = true;
              cUser = req.body.mail;
            });
          }
      });
    }
});

app.post('/login', (req, res, next) => {
  User.findOne({mail: req.body.lmail}, function(err, obj) {
      if(obj == null) {
        res.render("in", {h: false, fn: "User not found, sign up first!"});
      } else {
        bcrypt.compare(req.body.lpw, obj.pw, function(err, match) {
          if (match) {
            res.render("inlogged", {gr: "Password database management", h: true,  fn: "", ln: ""});
            req.session.user = obj;
            req.session.save();
            signed = true;
            cUser = obj.mail;
          } else {
            res.render("in", {h: false, fn: "Wrong password!"});
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
      res.render("passforgot", {fn: `Unknown mail address.`});
    } else {
      let urlId = obj._id.valueOf();
      let urlTime = Date.now();

      var message = {
        from: process.env.MAIL_USER,
        to: req.body.fmail,
        subject: "Password database - reset your password",
        text: `Hello user. This is your key: http://passtore.net/pass/${urlId}/${urlTime}`
      } 
      transport.sendMail(message, function(err, info) {
        if(err) {
            console.log(err);
        } else {
            res.render("passforgot", {fn: `E-mail sent.`});
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
      if(req.body.npw == "" || req.body.npwr == "") {
        res.render("passnew", {fn: `Fill all of the fields.`});
      } else if(difTime > 180000) {
        res.render("passnew", {fn: `This link expired, generate a new one.`});
      } else if(req.body.npw != req.body.npwr) {
        res.render("passnew", {fn: `Passwords do not match.`});
      } else {
        User.findOne({_id: ObjectId(urlId2)}, function(err, obj) {
          if(err) {
            res.render("passnew", {fn: `Link is not valid.`});
          } else {
            bcrypt.hash(req.body.npw, 10, function(err, hash) {
              User.updateOne({_id: ObjectId(urlId2)}, {pw: hash}, function(err, obj) {});
            });
            res.render("in", {h: false, fn: `New password set! Use it for logging in.`});
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
  lg: {
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
  req.session.destroy();
  signed = false;
  res.render("in", {h: true});
})


//one-password operations
app.post('/passadd', (req, res, next) => {
  if(signed) {
      Pass.findOne({mail: cUser, wn: req.body.awn}, function(err, obj) {
        if(req.body.awn != "" && obj != null) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj.pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          res.render("inlogged", {gr: "Password database management", h: false, fn: `Data for ${req.body.awn} have already been added by you!`, ln: `Login: ${obj.lg}, password: ${decrPw}`});
        } else if(req.body.awn == "" || req.body.alg == "" || req.body.apw == "") {
          res.render("inlogged", {gr: "Password database management", h: false, fn: `Fill all of the fields - web name, login & password!.`, ln: ""});
        } else {
          const cipher = crypto.createCipheriv(algorithm, Securitykey, initVector);
          let encrPw = cipher.update(req.body.apw, "utf-8", "hex");
          encrPw += cipher.final("hex");
          let newPass = new Pass ({
            mail: cUser,
            wn: req.body.awn,
            lg: req.body.alg,
            pw: encrPw
          });
          newPass.save();
          console.log("check");
          res.render("inlogged", {gr: "Password database management", h: false, fn: `Password for ${req.body.awn} saved.`, ln: ""});
        }
      }); 
  }
});

app.post('/passfind', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.fwn}, function(err, obj) {
        if(obj == null) {
          res.render("inlogged", {gr: "Password database management", h: false, fn: `Password for ${req.body.fwn} not found!`, ln: ``});
        } else {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj.pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          res.render("inlogged", {gr: "Password database management", h: false, fn: `Login: ${obj.lg}`, ln: `Password: ${decrPw}`});

        }
    });
  }
});

app.post('/passupdate', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.uwn}, function(err, obj) {
      if(obj == null) {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `Data for ${req.body.awn} not found!`, ln: ``});
      } else {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `Data for ${req.body.uwn} updated!`, ln: ``});
      }
    });
    if(req.body.unlg != "") { 
      Pass.updateOne({mail: cUser, wn: req.body.uwn}, {lg: req.body.unlg}, function(err, obj) {});
    }
    if(req.body.unpw != "") { 
      const cipher = crypto.createCipheriv(algorithm, Securitykey, initVector);
      let encrPw = cipher.update(req.body.unpw, "utf-8", "hex");
      encrPw += cipher.final("hex");
      Pass.updateOne({mail: cUser, wn: req.body.uwn}, {pw: encrPw}, function(err, obj) {});
    }  
  }
});

app.post('/passdelete', (req, res, next) => {
  if(signed) {
    Pass.findOne({mail: cUser, wn: req.body.dwn}, function(err, obj) {
      if(obj == null) {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `Password for ${req.body.dwn} not found!`, ln: ``});
      } else {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `Password for ${req.body.dwn} deleted!`, ln: ``});
      }
    });

    Pass.deleteOne({mail: cUser, wn: req.body.dwn}, function(err, obj) {});
  }
});

app.post('/hideannc', (req, res, next) => {
  if(signed) {
    res.render("inlogged", {gr: "Password database management", h: true, fn: ``, ln: ``});
  }
});

//table of passwords
app.post('/sapdef', (req, res, next) => {
  if(signed) {
    Pass.find({mail: cUser}, function(err, obj) {
      if(obj == null) {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `No passwords found`, ln: ``});
      } else {
        let arr = [];
        for(let i = 0; i < obj.length; i++) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj[i].pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          arr.push([obj[i].wn, obj[i].lg, decrPw]);
        }
        res.render("table", arrx=arr);
      }
    });
  }
})

app.post('/sapsort1', (req, res, next) => {
  if(signed) {
    Pass.find({mail: cUser}, function(err, obj) {
      if(obj == null) {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `No passwords found`, ln: ``});
      } else {
        let arr = [];
        for(let i = 0; i < obj.length; i++) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj[i].pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          arr.push([obj[i].wn, obj[i].lg, decrPw]);
        }
        arr.sort();
        res.render("table", arrx=arr);
      }
    });
  }
});

app.post('/sapsort2', (req, res, next) => {
  if(signed) {
    Pass.find({mail: cUser}, function(err, obj) {
      if(obj == null) {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `No passwords found`, ln: ``});
      } else {
        let arr = [];
        for(let i = 0; i < obj.length; i++) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj[i].pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          arr.push([obj[i].wn, obj[i].lg, decrPw]);
        }
        arr.sort((a, b) => (a[1] > b[1] ? 1 : -1))
        res.render("table", arrx=arr);
      }
    });
  }
});

app.post('/sapsort3', (req, res, next) => {
  if(signed) {
    Pass.find({mail: cUser}, function(err, obj) {
      if(obj == null) {
        res.render("inlogged", {gr: "Password database management", h: false, fn: `No passwords found`, ln: ``});
      } else {
        let arr = [];
        for(let i = 0; i < obj.length; i++) {
          const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
          let decrPw = decipher.update(obj[i].pw, "hex", "utf-8");
          decrPw += decipher.final("utf8");
          arr.push([obj[i].wn, obj[i].lg, decrPw]);
        }
        arr.sort((a, b) => (a[2] > b[2] ? 1 : -1))
        res.render("table", arrx=arr);
      }
    });
  }
});

app.listen(port, function() {
    console.log(`Server running on port ${port}`);
})