var express = require('express');
var ejs = require('ejs');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var Luno = require('luno');
var luno = new Luno({
  key: process.env.KEY,
  secret: process.env.SECRET,
  sandbox: process.env.SANDBOX === 'true'
})
var CSRF = require('luno-csrf');
var csrf = new CSRF(luno);

var app = express();

app.set('views', './views');
app.set('view engine', 'ejs');

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(luno.session());


app.get('/', function(req, res, next) {
  res.render('home', {
    user: req.user,
    title: 'Homepage'
  });
});


app.get('/login', csrf.middleware('login'), function(req, res, next) {
  if (req.user) return res.redirect('/dashboard');

  res.render('login', {
    title: 'Login',
    csrf: req.csrf.login,
    error: req.query.error
  });
});

app.post('/login', csrf.validateMiddleware('login'), function(req, res, next) {
  luno.post('/users/login', {}, {
    email: req.body.email,
    password: req.body.password,
    session: {
      id: req.session.id,
      ip: req.connection.remoteAddress,
      user_agent: req.headers['user-agent']
    }
  }, function(err, response) {
    if (err) {
      console.error('Login error', err);
      return res.redirect('/login?error=' + encodeURIComponent(err.message));
    }

    res.redirect('/dashboard');
  });
});



app.get('/signup', csrf.middleware('signup'), function(req, res, next) {
  if (req.user) return res.redirect('/dashboard');

  res.render('signup', {
    title: 'Sign up',
    csrf: req.csrf.signup,
    error: req.query.error
  });
});

app.post('/signup', csrf.validateMiddleware('signup'), function(req, res, next) {
  luno.post('/users', {}, {
    name: req.body.name,
    email: req.body.email,
    password: req.body.password
  }, function(err, user) {
    if (err) {
      console.error('Signup (create user) error', err);
      return res.redirect('/signup?error=' + encodeURIComponent(err.message));
    }

    // associate the session (used for CSRF) with the new user
    luno.patch('/sessions/' + req.session.id, {}, {
      user_id: user.id,
      ip: req.connection.remoteAddress,
      user_agent: req.headers['user-agent']
    }, function(err) {
      if (err) {
        console.error('Signup (session) error', err);
        return res.redirect('/signup?error=' + encodeURIComponent(err.message));
      }

      res.redirect('/dashboard');
    });
  });
});


// ensure a user is logged in for all /dashboard routes
app.use('/dashboard', function(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
});

app.get('/dashboard', function(req, res, next) {
  res.render('dashboard', {
    title: 'Dashboard',
    user: req.user
  });
});


app.get('/logout', function(req, res, next) {
  if (!req.session) return res.redirect('/login');

  luno.delete('/sessions/' + req.session.id, {}, function(err) {
    if (err) return next(err);

    res.redirect('/');
  });
});


// Error handling
app.use(function(req, res) {
  res.status(404);
  res.render('error', {
    title: 'Page Not Found'
  });
});

app.use(function(err, req, res, next) {
  console.error('Error', err);
  res.status(err.status || 500);

  res.render('error', {
    title: 'Error: ' + err.message
  });
});


app.listen(4000, function() {
  console.log('Listening on port 4000');
});
