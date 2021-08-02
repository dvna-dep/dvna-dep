var router = require("express").Router();
var appHandler = require("../core/appHandler");
var authHandler = require("../core/authHandler");

module.exports = function () {
  router.get("/", authHandler.isAuthenticated, authHandler.initializeRatingState, function (req, res) {
    res.redirect("/learn");
  });

  router.get("/usersearch", authHandler.isAuthenticated, authHandler.initializeRatingState, function (req, res) {
    res.render("app/usersearch", {
      output: null,
      securityRating: req.query.securityRating,
    });
  });

  router.get("/ping", authHandler.isAuthenticated, authHandler.initializeRatingState, function (req, res) {
    res.render("app/ping", {
      output: null,
      securityRating: req.query.securityRating,
    });
  });

  router.get("/bulkproducts", authHandler.isAuthenticated, authHandler.initializeRatingState, function (req, res) {
    res.render("app/bulkproducts", { legacy: req.query.legacy });
  });

  router.get("/products", authHandler.isAuthenticated, authHandler.initializeRatingState, appHandler.listProducts);

  router.get(
    "/modifyproduct",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    appHandler.modifyProduct
  );

  router.get("/useredit", authHandler.isAuthenticated, authHandler.initializeRatingState, appHandler.userEdit);

  router.get("/calc", authHandler.isAuthenticated, authHandler.initializeRatingState, function (req, res) {
    res.render("app/calc", { output: null });
  });

  router.get("/admin", authHandler.isAuthenticated, authHandler.initializeRatingState, function (req, res) {
    var globalRating = req.session.ratingState[req.query.vuln];
    res.render("app/admin", {
      admin: req.user.role == "admin",
      securityRating: globalRating,
      vuln: req.query.vuln,
    });
  });

  router.get(
    "/admin/usersapi/",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    authHandler.isAdmin,
    appHandler.listUsersAPI
  );

  router.get(
    "/admin/users/",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    authHandler.isAdmin,
    function (req, res) {
      vuln3 = "a3_sensitive_data";
      vuln5 = "a5_broken_access_control";
      var a3Rating = req.session.ratingState["a3_sensitive_data"];
      var a5Rating = req.session.ratingState["a5_broken_access_control"];
      res.render("app/adminusers", {
        a3Rating: a3Rating,
        a5Rating: a5Rating,
        admin: req.user.role,
        vuln3: vuln3,
        vuln5: vuln5,
      });
    }
  );

  router.get(
    "/admin/users/toggle",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    function (req, res) {
      if (req.session.ratingState[req.query.vuln] == 1)
        req.session.ratingState[req.query.vuln] = 0;
      else req.session.ratingState[req.query.vuln] = 1;
      res.redirect("/app/admin/users/");
    }
  );

  router.get(
    "/admin/toggle/a5",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    function (req, res) {
      if (req.session.ratingState["a5_broken_access_control"] == 1)
        req.session.ratingState["a5_broken_access_control"] = 0;
      else req.session.ratingState["a5_broken_access_control"] = 1;
      res.render("app/admin", {
        admin: req.user.dataValues.role == "admin",
        securityRating: req.session.ratingState["a5_broken_access_control"],
        vuln: "a5_broken_access_control",
      });
    }
  );

  router.get("/redirect", appHandler.redirect);

  router.post(
    "/usersearch",
    authHandler.isAuthenticated, authHandler.initializeRatingState,
    appHandler.userSearch
  );

  router.post("/ping", authHandler.isAuthenticated, authHandler.initializeRatingState, appHandler.ping);

  router.post(
    "/products",
    authHandler.isAuthenticated, authHandler.initializeRatingState, 
    appHandler.productSearch
  );

  router.post(
    "/modifyproduct",
    authHandler.isAuthenticated, authHandler.initializeRatingState, 
    appHandler.modifyProductSubmit
  );

  router.post(
    "/useredit",
    authHandler.isAuthenticated, authHandler.initializeRatingState, 
    appHandler.userEditSubmit
  );

  router.get(
    "/useredit/toggle",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    function (req, res) {
      if (req.session.ratingState[req.query.vuln] == 1)
        req.session.ratingState[req.query.vuln] = 0;
      else req.session.ratingState[req.query.vuln] = 1;
      res.redirect("/app/useredit/");
    }
  );

  router.post("/calc", authHandler.isAuthenticated, authHandler.initializeRatingState, appHandler.calc);

  router.post(
    "/bulkproducts",
    authHandler.isAuthenticated, authHandler.initializeRatingState, 
    appHandler.bulkProducts
  );

  router.post(
    "/bulkproductslegacy",
    authHandler.isAuthenticated, authHandler.initializeRatingState, 
    appHandler.bulkProductsLegacy
  );

  router.get('/reset-db', appHandler.resetdb);

  return router;
};
