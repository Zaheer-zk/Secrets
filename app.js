require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const mongoose = require('mongoose')
const encrypt = require('mongoose-encryption')
// const md5 = require('md5') level 2

const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')

const bcrypt = require('bcrypt')
const saltRounds = 10

const GoogleStrategy = require('passport-google-oauth20').Strategy
const findorCreate = require('mongoose-findorcreate')

const app = express()

app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }))
app.use(passport.initialize())
app.use(passport.session())

mongoose.connect(
  'mongodb+srv://admin-zaheer-secrets:secrets@cluster0.vchzu.mongodb.net/userDB',
  {
    useNewUrlParser: true,
  }
)

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  googleId: String,
  secret: String,
})
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findorCreate)

// ################ Level 3 Authentication #############

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRETS,
//   encryptedField: ['password'],
// })

const User = mongoose.model('User', userSchema)
passport.use(User.createStrategy())

passport.serializeUser(function (user, done) {
  done(null, user.id)
})

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user)
  })
})

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.Client_ID,
      clientSecret: process.env.Client_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    function (accessToken, refreshToken, profile, cb) {
      // var profile = profile.displayName
      User.findOrCreate(
        { googleId: profile.id, name: profile.displayName },
        function (err, user) {
          return cb(err, user)
        }
      )
    }
  )
)

app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/', (req, res) => {
  res.render('home')
})

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }))

app.get(
  '/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets')
  }
)

app.get('/register', (req, res) => {
  res.render('register')
})

app.get('/login', (req, res) => {
  res.render('login')
})

// app.get('/secrets', (req, res) => {
//   if (req.isAuthenticated()) {
//     res.render('secrets')
//   } else {
//     res.redirect('/login')
//   }
// })

app.get('/secrets', function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, foundUsers) {
    if (err) {
      console.log(err)
    } else {
      if (foundUsers) {
        res.render('secrets', {
          usersWithSecrets: foundUsers,
        })
      }
    }
  })
})

app.get('/submit', function (req, res) {
  if (req.isAuthenticated()) {
    res.render('submit')
  } else {
    res.redirect('/login')
  }
})

app.post('/submit', function (req, res) {
  const submittedSecret = req.body.secret

  //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user)

  User.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err)
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret
        foundUser.save(function () {
          res.redirect('/secrets')
        })
      }
    }
  })
})

app.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/')
})

// ##################### Level 4 Authentication login #####################

// app.post('/register', (req, res) => {
//   bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
// Store hash in your password DB.
//     const newUser = new User({
//       email: req.body.username,
// password: md5(req.body.password),
//       password: hash,
//     })
//     newUser.save((err) => {
//       if (err) {
//         console.log(err)
//       } else {
//         res.render('secrets')
//       }
//     })
//   })
// })

// app.post('/login', (req, res) => {
//   const username = req.body.username
// const password = md5(req.body.password)
//   const password = req.body.password

//   User.findOne({ email: username }, (err, userFound) => {
//     if (err) {
//       console.log(err)
//     } else {
//       if (userFound) {
//         bcrypt.compare(password, userFound.password, function (err, result) {
//           if (result == true) {
//             res.render('secrets')
//           }
//         })
//       }
//     }
//   })
// })

// ################################   Level 5 ########################

app.post('/register', (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err)
        res.redirect('/register')
      } else {
        passport.authenticate('local')(req, res, () => {
          res.redirect('/secrets')
        })
      }
    }
  )
})

app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  })
  req.login(user, (err) => {
    if (err) {
      console.log(err)
    } else {
      passport.authenticate('local')(req, res, () => {
        res.redirect('/secrets')
      })
    }
  })
})

let port = process.env.PORT

if (port == null || port == undefined) {
  port = 3000
}

app.listen(port, () => {
  console.log('listening on http://localhost:3000')
})
