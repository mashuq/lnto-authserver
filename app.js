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
app.listen(port, () => console.log(`LNTO Authserver listening on port ${port}!`));

redisClient.on('connect', function () {
    console.log('redis server connected');
});

app.post('/createUser', async function (req, res) {
    if (!req.body.username || !req.body.password) {
        res.status(400).json({ message: "Username & Password is required" });
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
            res.status(422).json({ message: "Username already taken" });
        }
    } catch (error) {
        res.status(500).send({ data: String(error) });
    }
});

app.post('/getToken', async function(req, res) {
    if (!req.body.username || !req.body.password) {
        res.status(400).json({ message: "Username & Password is required" });
    }
    let username = req.body.username;
    let password = req.body.password;
    let uuid = null;
    try{
        let result = await redisClient.hgetallAsync(username);
        if (null == result) {
            res.status(401).json({ message: "Invalid Username & Password" });
        } else {
            uuid = result.uuid;
            let passwordMatches = await bcrypt.compare(password, result.password);
            if(passwordMatches){
                let payload = { uuid: uuid };
                let token = jwt.sign(payload, privateKEY, config.signAndVerifyOptions);
                let responsePayload = { auth: true, token: token, uuid: uuid };
                res.status(200).json(responsePayload);
            }else{
                res.status(401).json({ message: "Invalid Username & Password" });
            }
        }
    }catch(error){
        res.status(500).json({ message: String(error) });
    }
});

app.post('/verifyToken', async function(req, res) {
    let token = req.headers['x-access-token'];
    if (!token) {
        return res.status(400).json({ auth: false, message: 'No token provided.' });
    }

    jwt.verify(token, publicKEY, config.signAndVerifyOptions, function (error, decoded) {
        if (error) {
            return res.status(500).json({ auth: false, message: 'Failed to authenticate token.' });
        }
        return res.status(200).json(decoded);
    });    
});
