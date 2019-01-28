let restify = require('restify');
let corsMiddleware = require('restify-cors-middleware')
let errors = require('restify-errors');
let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');
let redis = require('redis');
let util = require('util');
let client = redis.createClient();
let server = restify.createServer();
let bluebird = require("bluebird");
let uuidv4 = require('uuid/v4');
let config = require('./config');
const fs = require('fs');
bluebird.promisifyAll(redis);

let privateKEY = fs.readFileSync('./private.key', 'utf8');
let publicKEY = fs.readFileSync('./public.key', 'utf8');
let saltRounds = 10;

let restifyBodyParser = require('restify-plugins').bodyParser;
server.use(restifyBodyParser());


let cors = corsMiddleware({
    preflightMaxAge: 5, //Optional
    origins: ['http://localhost:3000'],
    allowHeaders: ['x-access-token'],
    exposeHeaders: ['API-Token-Expiry']
})

server.pre(cors.preflight);
server.use(cors.actual);

server.post('/createUser', (req, res, next) => {
    if (!req.body.username || !req.body.password) {
        return next(
            new errors.InvalidContentError("Expects username and password"),
        );
    }
    let username = req.body.username;
    let password = req.body.password;

    client.hgetallAsync(username).then(
        result => {
            if (null == result) {
                return bcrypt.hash(password, saltRounds)
            } else {
                throw "Username already taken";
            }
        },
        error => {
            throw error;
        }
    ).then(
        result => {
            let hashedPassword = result;
            let uuid = uuidv4();
            let payload = {
                username: username,
                password: hashedPassword,
                uuid: uuid,
                active: true
            };
            return client.hmsetAsync(username, payload);
        }
    ).then(
        result => {
            res.send(201, "User Created");
        },
        error => {
            return next(
                new errors.InternalServerError(error),
            );
        }
    );

    next();

});

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

client.on('connect', function () {
    console.log('redis server connected');
});

server.listen(8080, function () {
    console.log('%s listening at %s', server.name, server.url);
});