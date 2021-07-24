var db = require('../models')
var bCrypt = require('bcrypt')
var md5 = require('md5')
var vh = require('./validationHandler')
var cryptoRandomString = require('crypto-random-string')
var s512 = require('hash.js/lib/hash/sha/512')
var coolDownTime = 5*60*1000 // 5 mins
const ratingState = require('../config/ratingState')

const pwLength = "- Must contain at least 8 characters<br>"
const pwLower = "- Must contain at least 1 lowercase letter<br>"
const pwUpper = "- Must contain at least 1 uppercase letter<br>"
const pwNumber = "- Must contain at least 1 number<br>"
const pwSpec = "- Must contain at least 1 special character"
const badPWmsg = "Bad Password:<br>" + pwLength + pwLower + pwUpper + pwNumber + pwSpec

// TFA code start
//modeled after https://wanago.io/2019/07/22/nodejs-two-factor-authentication/
var speakeasy = require('speakeasy');
var QRCode = require ('qrcode');

function getTwoFactorAuthenticationCode() {
	const secretCode = speakeasy.generateSecret({
		name: 'DVNA-DEP'
	});
	return {
		otpauthUrl: secretCode.otpauth_url,
		base32: secretCode.base32,
	};
}

module.exports.verifyTwoFactorAuthenticationCode = async function (twoFactorAuthenticationCode, user) {
	return speakeasy.totp.verify({
		secret: user.twoFactorAuthenticationCode,
		encoding: 'base32',
		token: twoFactorAuthenticationCode,
	});
}

function respondWithQRCode(data, response) {
	QRCode.toFileStream(response, data);
}

async function saveUser2FA(user, base32){
	user.twoFactorAuthenticationCode = base32;
	await user.save();
}

async function enable2FA(user){
	user.isTwoFactorAuthenticationEnabled = true;
	await user.save();
}

module.exports.generateTwoFactorAuthenticationCode = async function (req, res){
	const user = req.user;
	const {
		otpauthUrl,
		base32,
	} = getTwoFactorAuthenticationCode();
	await saveUser2FA(user, base32);
	respondWithQRCode(otpauthUrl, res);
}

module.exports.turnOnTwoFactorAuthentication = async function(req, res, next){
	const { twoFactorAuthenticationCode } = req.body;
	const user = req.user;
	const isCodeValid = await verifyTwoFactorAuthenticationCode(
		twoFactorAuthenticationCode, user
	);
	if (isCodeValid) {
		await enable2FA(user);
		res.status(200).send();
		res.flash(`2FA enabled for user ${user.login}`, true);
	} else {
		res.send(401);
	}
}
// TFA code end

function sha512 (val) {
	return s512().update(val).digest('hex')
}

var createHash = function (password) {
	return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
}

module.exports.isAdmin = function (req, res, next){
	var a5securityRating = ratingState['a5_broken_access_control']
	if(a5securityRating == 1) {
		authenticateIsAdmin(req, res, next)
	}
	else{
		next()
	}
}

function authenticateIsAdmin(req, res, next){
	if(req.user.role=='admin')
	{
		next()
	} else
		res.status(401).send('Unauthorized')
} 


module.exports.isAuthenticated = function (req, res, next) {
	if (req.isAuthenticated()) {
		req.flash('authenticated', true)
		return next();
	}
	res.redirect('/login');
}

module.exports.isNotAuthenticated = function (req, res, next) {
	if (!req.isAuthenticated())
		return next();
	res.redirect('/learn');
}

module.exports.forgotPw = function (req, res) {
	if (req.body.login) {
		db.User.find({
			where: {
				'login': req.body.login
			}
		}).then(user => {
			if (user) {			
				if(req.body.securityRating == '0'){
					// Send reset link via email happens here
					var md5token = md5(req.body.login);
					req.flash('info', 'Email has been sent < http://127.0.0.1:9090/resetpw?login='+req.body.login+'&token=' + md5token+'&securityRating='+ req.body.securityRating + ' >')
					res.redirect('/login')
				}
				else if(req.body.securityRating == '1'){
					db.Passreset.findAll({limit:1,where:{'userId':user.id},order:[['createdAt','DESC']]}).then(record => {
						passreset = record[0]
						if(!passreset || passreset.used==true || (Date.now() - passreset.requestedAt)>coolDownTime){
							pr = new db.Passreset()
							var token = cryptoRandomString(30)
							pr.userId = user.id
							pr.used = false
							pr.requestedAt = Date.now()
							pr.tokenHash = sha512(token)
							pr.save()
							// SEND_EMAIL (token) at this step
							req.flash('info', 'If account exists, you will get an email on the registered email' + '< http://127.0.0.1:9090/resetpw?login='+req.body.login+'&token=' + token+'&securityRating='+ req.body.securityRating+ ' >' )
							res.redirect('/login')
						}else{
							// Cooldown time to prevent DoS
							req.flash('info', 'If account exists, you will get an email on the registered email <cooldown>')
							res.redirect('/login')
						}
					})
				}
			} else {
				if(req.body.securityRating == '0'){
					req.flash('danger', "Invalid login username")
					res.redirect('/forgotpw')
				}
				else if(req.body.securityRating == '1'){
					req.flash('info', 'If account exists, you will get an email on the registered email <note: invalid>')
					res.redirect('/login')
				}
			}
		})
	} else {
		if(req.body.securityRating == '0'){
			req.flash('danger', "Invalid login username")
		}
		else if(req.body.securityRating == '1'){
			req.flash('danger', "Error, Username contains special charecters")
		}
		res.redirect('/forgotpw')
	}
}

module.exports.resetPw = function (req, res) {
	if(req.query.securityRating == '0'){
		if (req.query.login) {
			db.User.find({
				where: {
					'login': req.query.login
				}
			}).then(user => {
				if (user) {
					if (req.query.token == md5(req.query.login)) {
						res.render('resetpw', {
							login: req.query.login,
							token: req.query.token,
							securityRating: req.query.securityRating
						})
					} else {
						req.flash('danger', "Invalid reset token")
						res.redirect('/forgotpw')
					}
					
				} else {
					req.flash('danger', "Invalid login username")
					res.redirect('/forgotpw')
				}
			})
		} else {
			req.flash('danger', "Invalid login username")
			res.redirect('/forgotpw')
		}	
	}
	else if(req.query.securityRating == '1'){
		if (vh.vCode(req.query.login)&&vh.vCode(req.query.token)) {
			db.User.find({
				where: {
					'login': req.query.login
				}
			}).then(user => {
				if (user) {
					db.Passreset.find({where:{'tokenHash': sha512(req.query.token)}}).then(resetpass => {
						if(resetpass&&((Date.now() - resetpass.requestedAt)<coolDownTime)&&resetpass.used==false){
							res.render('resetpw', {
								login: req.query.login,
								token: req.query.token,
								securityRating: req.query.securityRating
							})							
						}else if(resetpass){
							req.flash('warning', "Link Expired")
							res.redirect('/forgotpw')							
						} else {
							req.flash('danger', "Invalid reset link")
							res.redirect('/forgotpw')
						}
					})
				} else {
					req.flash('danger', "Invalid reset link")
				res.redirect('/forgotpw')
			}
		})
		} else {
			req.flash('danger', "Invalid reset link")
			res.redirect('/forgotpw')
		}
	}
}

module.exports.resetPwSubmit = function (req, res) {
	if(req.body.securityRating == '0'){
		if (req.body.password && req.body.cpassword && req.body.login && req.body.token) {
			if (req.body.password == req.body.cpassword) {
				db.User.find({
					where: {
						'login': req.body.login
					}
				}).then(user => {
					if (user) {
						if (req.body.token == md5(req.body.login)) {
							user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
							user.save().then(function () {
								req.flash('success', "Passowrd successfully reset <login: "+ req.body.login + " // pw: "+ req.body.password +">")
								res.redirect('/login')
							})
						} else {
							req.flash('danger', "Invalid reset token")
							res.redirect('/forgotpw')
						}
					} else {
						req.flash('danger', "Invalid login username")
						res.redirect('/forgotpw')
					}
				})
			} else {
				req.flash('danger', "Passwords do not match")
				res.render('resetpw', {
					login: req.body.login,
					token: req.body.token,
					securityRating: req.body.securityRating
				})
			}
		} else {
			req.flash('danger', "Invalid request")
			res.redirect('/forgotpw')
		}
	}
	else if(req.body.securityRating == '1'){
		if (vh.vPassword(req.body.password) && req.body.cpassword && vh.vCode(req.body.login) && vh.vString(req.body.token)) {
			if (req.body.password == req.body.cpassword) {
				db.User.find({
					where: {
						'login': req.body.login
					}
				}).then(user => {
					if (user) {
						db.Passreset.find({where:{'tokenHash': sha512(req.body.token)}}).then(resetpass => {
							if(resetpass&&((Date.now() - resetpass.requestedAt)<coolDownTime)&&resetpass.used==false){
								user.password = createHash(req.body.password)
								user.save()
								resetpass.used = true
								resetpass.save()
								req.flash('success',"Password successfuly changed <login: " + req.body.login + " // new pw: " + req.body.password + ">")
								res.redirect('/login')
							}else if(resetpass){
								req.flash('warning', "Link Expired")
								res.redirect('/forgotpw')							
							} else {
								req.flash('danger', "Invalid reset link")
								res.redirect('/forgotpw')
							}
						})
					} else {
						req.flash('danger', "Invalid reset link")
						res.redirect('/forgotpw')
					}
				})
			} else {
				req.flash('danger', "Passwords do not match")
				res.render('resetpw', {
					login: req.body.login,
					token: req.body.token,
					securityRating: req.body.securityRating
				})
			}
		} else {
			req.flash('danger', badPWmsg)
			res.render('resetpw', {
				login: req.body.login,
				token: req.body.token,
				securityRating: req.body.securityRating
			})
		}
	}
}
