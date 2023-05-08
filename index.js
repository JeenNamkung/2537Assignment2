require('./utils.js');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require('joi');

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

app.set('view engine', 'ejs');

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret,
	},
});

app.use(
	session({
		secret: node_session_secret,
		store: mongoStore,
		saveUninitialized: false,
		resave: true,
	})
);

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
  console.log("req.session:", req.session); // Debug statement
  console.log("req.session.user_type:", req.session.user_type); // Debug statement
  if (req.session.user_type === "admin") {
    return true;
  }
  return false;
}



function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
		console.log(isAdmin(req));
    res.status(403);
    res.render("403", { error: "This clearance is above your paygrade." });
    return;
  } else {
    next();
  }
}



app.get('/', (req, res) => {
	var isAuthenticated = req.session.authenticated || false;
	if (!isAuthenticated) {
		res.render('main');
	} else {
		res.render('index', { username: req.session.username });
	}
});

app.get("/nosql-injection", sessionValidation, async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, password: 1, username: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/signup', (req, res) => {
	res.render('signup');
});

app.post('/submit', async (req, res) => {
	var username = req.body.username;
	var email = req.body.email;
	var password = req.body.password;

	if (!email) {
		res.render('signupError', { error: 'Email' });
	}
	if (!username) {
		res.render('signupError', { error: 'Username' });
	}
	if (!password) {
		res.render('signupError', { error: 'Password' });
	}

	const schema = Joi.object({
		username: Joi.string().alphanum().max(20).required(),
		email: Joi.string().email().required(),
		password: Joi.string().max(20).required(),
	});

	const validationResult = schema.validate({ username, email, password });
	if (validationResult.error != null) {
		console.log(validationResult.error);
		res.render('signupError', { error: `${validationResult.error.message}` });
		return;
	}

	const user = await userCollection.findOne({ email: email });
	if (user) {
		res.render('signupError', { error: 'Email already exists'});
		return;
	}

	var hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({
		username: username,
		email: email,
		password: hashedPassword,
		user_type: 'user',
	});

	req.session.authenticated = true;
	req.session.username = username;
	req.session.cookie.maxAge = expireTime;

	res.redirect('/members');
});

app.get('/login', (req, res) => {
	res.render('login');
});

app.post('/loggingin', async (req, res) => {
	var email = req.body.email;
	var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
		res.render('loginError', { error: `${validationResult.error.message}` });
		return;
	}

	const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, user_type: 1, _id: 1 }).toArray();

	console.log(result);
	if (result.length === 0) {
		res.render('loginError', { error: 'Invalid email or password' });
		return;
	} else if (result.length > 1) {
		res.redirect('/loggedin');
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log('correct password');
		req.session.authenticated = true;
		req.session.email = email;
		req.session.username = result[0].username;
		req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedin');
		return;
	} else {
		res.render('loginError', { error: 'Invalid password', authenticated: req.session.authenticated });
		return;
	}
});

app.use('/loggedin', sessionValidation);

app.get('/loggedin', (req, res) => {
	if (req.session.authenticated) {
		res.redirect('/members');
	} else {
		res.redirect('/');
	}
});

app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect('/');
});

app.get('/members', (req, res) => {
	if (!req.session.authenticated) {
		res.redirect('/login');
	} else {
		res.render('members', { authenticated: req.session.authenticated, username: req.session.username });
	}
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
	const result = await userCollection.find().project({ username: 1, user_type: 1 }).toArray();
	res.render('admin', {
		users: result,
		username: req.session.username,
		user_type: req.session.user_type
	});
});

app.get('/promote/:username', async (req, res) => {
	var username = req.params.username;
	try {
		await userCollection.findOneAndUpdate({ username: username }, { $set: { user_type: 'admin' } });
		res.redirect('/admin');
	} catch (err) {
		console.log(err);
		res.send('Error promoting user');
	}
});

app.get('/demote/:username', async (req, res) => {
	var username = req.params.username;
	try {
		await userCollection.findOneAndUpdate({ username: username }, { $set: { user_type: 'user' } });
		res.redirect('/admin');
	} catch (err) {
		console.log(err);
		res.send('Error promoting user');
	}
});

app.use(express.static(__dirname + '/public'));

app.get('*', (req, res) => {
	res.status(404);
	res.render('404');
});

app.listen(port, () => {
	console.log('Node application listening on port ' + port);
});
