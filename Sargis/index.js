import express from "express";
import session from "express-session";
import path from "path";
import bcrypt from "bcrypt";
import passport from "passport";
import passportLocal from "passport-local";

const app = express();

let users = [];

app.use(session({
    secret : process.env.SESSION_SECRET,
    resave : false,
    saveUninitialized : false
}))
app.use(express.json());
app.use(express.urlencoded({ extended : true }));
app.use(passport.initialize());
app.use(passport.session());
passport.use(new passportLocal.Strategy({
    usernameField: "email"
}, async (email, password, done) => {
    const currentUser = users.find(user => user.email === email);

    if (currentUser === undefined) {
        return done(null, null, { message : "incorrect email"});
    }

    if (await bcrypt.compare(password, currentUser.passaword)) {
        return done(null, currentUser)
    }

    return done(null, null, { message : "incorrect password"});
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    done(null, users.find(user => id === user.id));
});


app.get("/register", checkNotAuthentication, (req, res) => {
    res.sendFile(path.resolve("public/register.html"));
});

app.post("/register", async (req, res) => {
    const {name, email, password} = req.body;
    const hashedPwd = await bcrypt.hash(password, 10);

    users.push({
        id: `${Math.random()}_${Date.now()}`,
        name,
        email,
        password: hashedPwd
    });
    console.log(users[0]);
    res.redirect("/login");
});

app.get("/login", checkNotAuthentication, (req, res) => {
    res.sendFile(path.resolve("public/login.html"));
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/local"
}));

app.use(checkAuthentication);

app.get("/", (req, res) => {
    res.sendFile(path.resolve("public/app.html"));
});

app.get("/logout", (req, res) => {
    req.logOut();
    res.redirect("/login");
})

function checkAuthentication(req, res, next) {
    if (req.isAuthenticated === false) {
        return res.redirect("/login");
    }

    next();
}

function checkNotAuthentication(req, res, next) {
    if (req.isAuthenticated === true) {
        return res.redirect("/");
    }

    next();
}

app.listen(process.env.PORT || 3001);