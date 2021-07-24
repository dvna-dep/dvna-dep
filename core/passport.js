var db = require('../models')
var LocalStrategy = require('passport-local').Strategy
var bCrypt = require('bcrypt')
var vh = require('./validationHandler')
var authHandler = require('./authHandler.js')


const pwLength = "- Must contain at least 8 characters<br>"
const pwLower = "- Must contain at least 1 lowercase letter<br>"
const pwUpper = "- Must contain at least 1 uppercase letter<br>"
const pwNumber = "- Must contain at least 1 number<br>"
const pwSpec = "- Must contain at least 1 special character"
const badPWmsg = "Bad Password:<br>" + pwLength + pwLower + pwUpper + pwNumber + pwSpec

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
                };
                if (!isValidPassword(user, password)) {
                    return done(null, false, req.flash('danger', 'Invalid Credentials'))
                };
                if (!user.isTwoFactorAuthenticationEnabled) {
                    return done(null, user);
                } else {
                    console.log(user);
                    const totpToken = req.body.twoFactorAuthenticationCode;
                    return authHandler.verifyTwoFactorAuthenticationCode(totpToken, user)
                    .then(()=> {return done(null, user)})
                    .catch(error => {
                            console.log(error);
                            res.send(401);
                    })
                };
            })
        }));

    var isValidPassword = function (user, password) {
        return bCrypt.compareSync(password, user.password);
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
                        if(req.body.securityRating == 0){
                            if (req.body.email && req.body.password && req.body.username && req.body.cpassword && req.body.name) {
                                if (req.body.cpassword == req.body.password) {
                                    db.User.create({
                                        email: req.body.email,
                                        password: createHash(password),
                                        name: req.body.name,
                                        login: username,
                                        isTwoFactorAuthenticationEnabled: false
                                    }).then(function (user) {
                                        return done(null, user)
                                    })
                                } else {
                                    return done(null, false, req.flash('danger', 'Passwords do not match'));
                                }
                            } else {
                                return done(null, false, req.flash('danger', 'Input field(s) missing'));
                            }   
                        } else if(req.body.securityRating >= 1){
                            if(!vh.vEmail(req.body.email)){
                                return done(null, false, req.flash('danger', 'Invalid Email'));
                            }
                            if(!vh.vPassword(req.body.password)){
                                return done(null, false, req.flash('danger', badPWmsg));
                            }
                            if (req.body.email && req.body.password && req.body.username && req.body.cpassword && req.body.name) {
                                if (req.body.cpassword == req.body.password) {
                                    db.User.create({
                                        email: req.body.email,
                                        password: createHash(password),
                                        name: req.body.name,
                                        login: username,
                                        isTwoFactorAuthenticationEnabled: false
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
                    }
                });
            };
            process.nextTick(findOrCreateUser)
        }));

    var createHash = function (password) {
        return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
    }

}
