var router = require("express").Router();
var vulnDict = require("../config/vulns");
var ratingsDict = require("../config/ratings");
var authHandler = require("../core/authHandler");

module.exports = function (passport) {
  router.get(
    "/",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    function (req, res) {
      res.redirect("/learn");
    }
  );

  router.get("/login", authHandler.isNotAuthenticated, authHandler.initializeRatingState, function (req, res) {
    res.render("login");
  });

  router.get(
    "/learn/vulnerability/:vuln",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    function (req, res) {
      var query_rating = req.query.securityRating
        ? req.query.securityRating
        : req.session.ratingState[req.params.vuln];
      req.session.ratingState[req.params.vuln] = query_rating;
      if (req.params.vuln == "a3_sensitive_data") {
        req.session.ratingState["a5_broken_access_control"] = 0;
      }
      res.render(
        "vulnerabilities/layout",
        {
          vuln: req.params.vuln,
          vuln_title: vulnDict[req.params.vuln],
          vuln_scenario: req.params.vuln + "/scenario",
          vuln_description: req.params.vuln + "/description",
          vuln_reference: req.params.vuln + "/reference",
          vulnerabilities: vulnDict,
          ratings: ratingsDict[req.params.vuln],
          securityRating: query_rating,
        },
        function (err, html) {
          if (err) {
            console.log(err);
            res.status(404).send("404");
          } else {
            res.send(html);
          }
        }
      );
    }
  );

  router.get(
    "/learn",
    authHandler.isAuthenticated,
    authHandler.initializeRatingState,
    function (req, res) {
      res.render("learn", { vulnerabilities: vulnDict });
    }
  );

  router.get("/register", authHandler.isNotAuthenticated, authHandler.initializeRatingState, function (req, res) {
    var query_rating = req.query.securityRating ? req.query.securityRating : 0;
    req.session.ratingState['register'] = query_rating;
    res.render("register", {
      ratings: ratingsDict["register"],
      securityRating: query_rating,
    });
  });

  router.get("/logout", function (req, res) {
    req.logout();
    req.session.destroy();
    res.redirect("/");
  });

  router.get("/forgotpw", authHandler.initializeRatingState, function (req, res) {
    var query_rating = req.query.securityRating ? req.query.securityRating : 0;
    req.session.ratingState['forgotpw'] = query_rating;
    res.render("forgotpw", {
      ratings: ratingsDict["forgotpw"],
      securityRating: query_rating,
    });
  });

  router.get("/resetpw", authHandler.initializeRatingState, authHandler.resetPw);

  router.post(
    "/login", authHandler.initializeRatingState, 
    passport.authenticate("login", {
      successRedirect: "/learn",
      failureRedirect: "/login",
      failureFlash: true,
    })
  );

  router.post("/register", authHandler.initializeRatingState, function (req, res, next) {
    passport.authenticate("signup", {
      successRedirect: "/learn",
      failureRedirect: "/register?securityRating=" + req.body.securityRating,
      failureFlash: true,
    })(req, res, next);
  });

  router.get("/createAdmin", authHandler.isNotAuthenticated, authHandler.initializeRatingState, function (req, res) {
    var query_rating = req.query.securityRating ? req.query.securityRating : 0;
    req.session.ratingState['register'] = query_rating;
    res.render("registerAdmin", {
      ratings: ratingsDict["register"],
      securityRating: query_rating,
    });
  });

  router.post("/createAdmin", authHandler.initializeRatingState, function (req, res, next) {
    passport.authenticate("signupadmin", {
      successRedirect: "/learn",
      failureRedirect: "/register?securityRating=" + req.body.securityRating,
      failureFlash: true,
    })(req, res, next);
  });

  router.post("/forgotpw", authHandler.initializeRatingState, authHandler.forgotPw);

  router.post("/resetpw", authHandler.initializeRatingState, authHandler.resetPwSubmit, function (req, res) {
    res.render("resetpw", {
      login: req.login,
      token: req.token,
      securityRating: req.securityRating,
    });
  });

  return router;
};
