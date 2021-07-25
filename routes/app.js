var router = require('express').Router()
const ratingState = require('../config/ratingState')
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

module.exports = function () {
    router.get('/', authHandler.isAuthenticated, function (req, res) {
        res.redirect('/learn')
    })

    router.get('/usersearch', authHandler.isAuthenticated, function (req, res) {
        res.render('app/usersearch', {
            output: null,
            securityRating: req.query.securityRating
        })
    })

    router.get('/ping', authHandler.isAuthenticated, function (req, res) {
        res.render('app/ping', {
            output: null,
            securityRating: req.query.securityRating
        })
    })

    router.get('/bulkproducts', authHandler.isAuthenticated, function (req, res) {
        res.render('app/bulkproducts',{legacy:req.query.legacy})
    })

    router.get('/products', authHandler.isAuthenticated, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProduct)

    router.get('/useredit', authHandler.isAuthenticated, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, function (req, res) {
        res.render('app/calc',{output:null})
    })

    router.get('/admin', authHandler.isAuthenticated, function (req, res) {
        var globalRating = ratingState[req.query.vuln]
        res.render('app/admin', {
            admin: (req.user.role == 'admin'),
            securityRating: globalRating,
            vuln: req.query.vuln
        })
    })

    router.get('/admin/usersapi/', authHandler.isAuthenticated, authHandler.isAdmin, appHandler.listUsersAPI)

    router.get('/admin/users/', authHandler.isAuthenticated, authHandler.isAdmin,function(req, res){
        vuln3 = 'a3_sensitive_data'
        vuln5 = 'a5_broken_access_control'
        var a3Rating = ratingState['a3_sensitive_data']
        var a5Rating = ratingState['a5_broken_access_control']
        res.render('app/adminusers', {
            a3Rating: a3Rating,
            a5Rating: a5Rating,
            admin: req.user.role,
            vuln3: vuln3,
            vuln5: vuln5
        })
    })

    router.get('/admin/users/toggle', authHandler.isAuthenticated, function (req, res) {
        if(ratingState[req.query.vuln] == 1)
            ratingState[req.query.vuln] = 0
        else
            ratingState[req.query.vuln] = 1
        res.redirect('/app/admin/users/')
    })

    router.get('/admin/toggle/a5', authHandler.isAuthenticated, function (req, res) {
        if(ratingState['a5_broken_access_control'] == 1)
            ratingState['a5_broken_access_control'] = 0
        else
            ratingState['a5_broken_access_control'] = 1
        res.render('app/admin', {
            admin: (req.user.dataValues.role == 'admin'),
            securityRating: ratingState['a5_broken_access_control'],
            vuln: 'a5_broken_access_control'
        })
    })
   
    router.get('/redirect', appHandler.redirect)

    router.post('/usersearch', authHandler.isAuthenticated, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit)

    router.get('/useredit/toggle', authHandler.isAuthenticated, function (req, res) {
        if(ratingState[req.query.vuln] == 1)
            ratingState[req.query.vuln] = 0
        else
            ratingState[req.query.vuln] = 1
        res.redirect('/app/useredit/')
    })

    router.post('/calc', authHandler.isAuthenticated, appHandler.calc)

    router.post('/bulkproducts',authHandler.isAuthenticated, appHandler.bulkProducts);

    router.post('/bulkproductslegacy',authHandler.isAuthenticated, appHandler.bulkProductsLegacy);

    return router
}
