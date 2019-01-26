let config = {
    signAndVerifyOptions : {
        issuer:  "Learn and Teach Online",
        subject:  "guybrush@learnandteach.online",
        audience:  "http://localhost",
        expiresIn:  "12h",
        algorithm:  "RS256"
    }
}

module.exports = config;
