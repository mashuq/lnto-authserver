const express = require('express')
const app = express();
let cors = require('cors')
const port = 8080;
let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');
let redis = require('redis');
let redisClient = redis.createClient();
let bluebird = require("bluebird");
let uuidv4 = require('uuid/v4');
let config = require('./config');
let fs = require('fs');
var bodyParser = require('body-parser')
bluebird.promisifyAll(redis);

let privateKEY = fs.readFileSync('./private.key', 'utf8');
let publicKEY = fs.readFileSync('./public.key', 'utf8');
let saltRounds = 10;



var corsOptions = {
    origin: 'http://localhost:3000',
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
}

app.use(cors(corsOptions));
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.listen(port, () => console.log(`Example app listening on port ${port}!`));

  

app.post('/createUser', async function (req, res) {
    //console.log(req);
    if (!req.body.username || !req.body.password) {
        return next(
            new errors.InvalidContentError("Expects username and password"),
        );
    }
    let username = req.body.username;
    let password = req.body.password;

    try {
        let result = await redisClient.hgetallAsync(username);
        if (null == result) {
            hashedPassword = await bcrypt.hash(password, saltRounds);
            let uuid = uuidv4();
            let payload = {
                username: username,
                password: hashedPassword,
                uuid: uuid,
                active: true
            };
            userCreation = await redisClient.hmsetAsync(username, payload);
            res.status(200).json({ message: "User Created Succesfully" });
        } else {
            console.log("Username already taken");
            res.status(422).json({ message: "Username already taken" });
        }
    } catch (error) {
        res.status(500).send({ data: String(error) });
    }
});


redisClient.on('connect', function () {
    console.log('redis server connected');
});

/*

server.post('/getToken', (req, res, next) => {
    if (!req.body.username || !req.body.password) {
        return next(
            new errors.InvalidContentError("Expects username and password"),
        );
    }

    let username = req.body.username;
    let password = req.body.password;
    let uuid = null;

    client.hgetallAsync(username).then(
        result => {
            if (null == result) {
                throw "Invalid Username and Password";
            } else {
                uuid = result.uuid;
                return bcrypt.compare(password, result.password);
            }
        },
        error => {
            throw error;
        }
    ).then(
        result => {
            if (result) {
                try {
                    var payload = { uuid: uuid };
                    var token = jwt.sign(payload, privateKEY, config.signAndVerifyOptions);
                    res.send(200, { auth: true, token: token });
                } catch (error) {
                    return next(
                        new errors.InternalServerError(error),
                    );
                }
            } else {
                return next(
                    new "Invalid Username and Password",
                );
            }
        },
        error => {
            return next(
                new errors.UnauthorizedError(error),
            );
        }
    );
    next();
});

server.post('/verifyToken', (req, res, next) => {
    var token = req.headers['x-access-token'];
    if (!token) {
        return res.send(400, { auth: false, message: 'No token provided.' });
    }

    jwt.verify(token, publicKEY, config.signAndVerifyOptions, function (error, decoded) {
        if (error) {
            return res.send(500, { auth: false, message: 'Failed to authenticate token.' });
        }
        return res.send(200, decoded);
    });

    next();
});


server.listen(8080, function () {
    console.log('%s listening at %s', server.name, server.url);
});

*/