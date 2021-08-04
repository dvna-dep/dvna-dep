var db = require('../models')
var LocalStrategy = require('passport-local').Strategy
var bCrypt = require('bcrypt')
var vh = require('./validationHandler')
const crypto = require("crypto");


const pwLength = "- Must contain at least 8 characters<br>"
const pwLower = "- Must contain at least 1 lowercase letter<br>"
const pwUpper = "- Must contain at least 1 uppercase letter<br>"
const pwNumber = "- Must contain at least 1 number<br>"
const pwSpec = "- Must contain at least 1 special character"
const badPWmsg = "Bad Password:<br>" + pwLength + pwLower + pwUpper + pwNumber + pwSpec

// array for names of password hash types
const hashTypes = ["MD5", "SHA-1", "SHA-256", "SHA-512", "bCrypt"];

const SALT_LENGTH = 32; //salt length in bytes 

module.exports = function (passport) {

    passport.serializeUser(function (user, done) {
        done(null, user.id)
    });

    passport.deserializeUser(function (uid, done) {
        db.User.findOne({
            where: {
                'id': uid
            }
        }).then(function (user) {
            if (user) {
                done(null, user);
            } else {
                done(null, false)
            }

        })
    })

    passport.use('login', new LocalStrategy({
            passReqToCallback: true
        },
        function (req, username, password, done) {
            db.User.findOne({
                where: {
                    'login': username
                }
            }).then(function (user) {
                if (!user) {
                    return done(null, false, req.flash('danger', 'Invalid Credentials'))
                }
                if (!isValidPassword(user, password)) {
                    return done(null, false, req.flash('danger', 'Invalid Credentials'))
                }
                return done(null, user);
            });
        }))
    

    // hash login password and compare to stored password hash
    var isValidPassword = function (user, password) {
        if (user.salt){
            password += user.salt; 
        };
        switch(user.hashtype) {
            case "MD5": 
                return crypto.createHash('md5').update(password).digest('hex') === user.password;
            case "SHA-1":
                return crypto.createHash('sha1').update(password).digest('hex') === user.password;
            case "SHA-256":
                return crypto.createHash('sha256').update(password).digest('hex') === user.password;
            case "SHA-512":
                return crypto.createHash('sha512').update(password).digest('hex') === user.password;
            case "bCrypt":
                return bCrypt.compareSync(password, user.password);
        }
    }
    
    passport.use('signup', new LocalStrategy({
            passReqToCallback: true
        },
        function (req, username, password, done) {
            findOrCreateUser = function () {
                db.User.findOne({
                    where: {
                        'email': req.body.email
                    }
                }).then(function (user) {
                    if (user) {
                        return done(null, false, req.flash('danger', 'Account Already Exists'));
                    } else {
                        if(req.body.securityRating == 1){ // Level 1: validate input
                            if(!vh.vEmail(req.body.email)){
                                return done(null, false, req.flash('danger', 'Invalid Email'));
                            };
                            if(!vh.vPassword(req.body.password)){
                                return done(null, false, req.flash('danger', badPWmsg));
                            };
                        };
                        if (req.body.email && req.body.password && req.body.username && req.body.cpassword && req.body.name && req.body.pwLevel) {
                            if (req.body.cpassword == req.body.password) {
                                var saltStr = '';
                                if (req.body.salt == 'true'){
                                    saltStr = genRandomString(SALT_LENGTH);
                                    password += saltStr; 
                                };
                                db.User.create({
                                    email: req.body.email,
                                    password: createHash(password, req.body.pwLevel),
                                    name: req.body.name,
                                    login: username,
                                    hashtype: hashTypes[req.body.pwLevel],
                                    salt: saltStr
                                }).then(function (user) {
                                    return done(null, user)
                                })
                            } else {
                                return done(null, false, req.flash('danger', 'Passwords do not match'));
                            }
                        } else {
                            return done(null, false, req.flash('danger', 'Input field(s) missing'));
                        }
                    }
                });
            };
            process.nextTick(findOrCreateUser)
        }));


        passport.use('signupadmin', new LocalStrategy({
            passReqToCallback: true
        },
        function (req, username, password, done) {
            findOrCreateUser = function () {
                db.User.findOne({
                    where: {
                        'email': req.body.email
                    }
                }).then(function (user) {
                    if (user) {
                        return done(null, false, req.flash('danger', 'Account Already Exists'));
                    } else {
                        if(req.body.securityRating == 1){ // Level 1: validate input
                            if(!vh.vEmail(req.body.email)){
                                return done(null, false, req.flash('danger', 'Invalid Email'));
                            };
                            if(!vh.vPassword(req.body.password)){
                                return done(null, false, req.flash('danger', badPWmsg));
                            };
                        };
                        if (req.body.email && req.body.password && req.body.username && req.body.cpassword && req.body.name && req.body.pwLevel) {
                            if (req.body.cpassword == req.body.password) {
                                var saltStr = '';
                                if (req.body.salt == 'true'){
                                    saltStr = genRandomString(SALT_LENGTH);
                                    password += saltStr; 
                                };
                                db.User.create({
                                    email: req.body.email,
                                    password: createHash(password, req.body.pwLevel),
                                    name: req.body.name,
                                    login: username,
                                    hashtype: hashTypes[req.body.pwLevel],
                                    role: 'admin',
                                    salt: saltStr
                                }).then(function (user) {
                                    return done(null, user)
                                })
                            } else {
                                return done(null, false, req.flash('danger', 'Passwords do not match'));
                            }
                        } else {
                            return done(null, false, req.flash('danger', 'Input field(s) missing'));
                        }
                    }
                });
            };
            process.nextTick(findOrCreateUser)
        }));
        
        
    // level corresponds to cracking difficult (0 for easiest, 4 for hardest)
    var createHash = function (password, level) {
        switch(level) {
            case "0": 
                return crypto.createHash('md5').update(password).digest('hex');
            case "1":
                return crypto.createHash('sha1').update(password).digest('hex');
            case "2":
                return crypto.createHash('sha256').update(password).digest('hex');
            case "3":
                return crypto.createHash('sha512').update(password).digest('hex');
            case "4":
                return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
        }
    }

    // salt generation function, from 
    // https://ciphertrick.com/salt-hash-passwords-using-nodejs-crypto/
    /**
     * generates random string of characters i.e salt
     * @function
     * @param {number} length - Length of the random string.
     */
    var genRandomString = function (length){
        return crypto.randomBytes(Math.ceil(length/2))
                .toString('hex') /** convert to hexadecimal format */
                .slice(0,length);   /** return required number of characters */
    };

}