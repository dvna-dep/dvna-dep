var router = require("express").Router();
var vulnDict = require("../config/vulns");
var ratingsDict = require("../config/ratings");
var authHandler = require("../core/authHandler");
var ratingState = require("../config/ratingState");

module.exports = function (passport) {
  router.get(
    "/",
    authHandler.isAuthenticated,
    authHandler.ensureTotp,
    function (req, res) {
      res.redirect("/learn");
    }
  );

  router.get("/login", authHandler.loginGate, function (req, res) {
    var query_rating = req.query.securityRating
      ? req.query.securityRating
      : ratingState["login"];
    ratingState["login"] = query_rating;
    res.render("login", {
      ratings: ratingsDict["login"],
      securityRating: query_rating,
    });
  });

  router.get(
    "/learn/vulnerability/:vuln",
    authHandler.isAuthenticated,
    authHandler.ensureTotp,
    function (req, res) {
      var query_rating = req.query.securityRating
        ? req.query.securityRating
        : ratingState[req.params.vuln];
      ratingState[req.params.vuln] = query_rating;
      if (req.params.vuln == "a3_sensitive_data") {
        ratingState["a5_broken_access_control"] = 0;
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
    authHandler.ensureTotp,
    function (req, res) {
      res.render("learn", { vulnerabilities: vulnDict });
    }
  );

  router.get("/register", authHandler.isNotAuthenticated, function (req, res) {
    var query_rating = req.query.securityRating ? req.query.securityRating : 0;
    ratingState["register"] = query_rating;
    res.render("register", {
      ratings: ratingsDict["register"],
      securityRating: query_rating,
    });
  });

  router.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
  });

  router.get("/forgotpw", function (req, res) {
    var query_rating = req.query.securityRating ? req.query.securityRating : 0;
    res.render("forgotpw", {
      ratings: ratingsDict["forgotpw"],
      securityRating: query_rating,
    });
  });

  router.get("/resetpw", authHandler.resetPw);

  router.post(
    "/login",
    passport.authenticate("local", { failureRedirect: "/login" }),
    function (req, res) {
      var rating = ratingState["login"];
      var user = req.user;
      if (rating == 0) {
        // no totp
        req.session.method = "plain";
        res.redirect("/learn");
      } else if (rating == 1) {
        if (!user.isTwoFactorAuthenticationEnabled) {
          req.flash(
            "danger",
            `Two Factor Authentication not enabled for user ${user.name}`
          );
        } else {
          req.session.method = "totp";
          res.redirect("/auth2fa");
        }
      }
    }
  );

  router.post("/register", function (req, res, next) {
    const rating = ratingState.register;
    const redirect = rating == 2 ? "/setup2fa" : "/learn";
    passport.authenticate("signup", {
      successRedirect: redirect,
      failureRedirect: "/register?securityRating=" + req.body.securityRating,
      failureFlash: true,
    })(req, res, next);
  });

  router.post("/forgotpw", authHandler.forgotPw);

  router.post("/resetpw", authHandler.resetPwSubmit, function (req, res) {
    res.render("resetpw", {
      login: req.login,
      token: req.token,
      securityRating: req.securityRating,
    });
  });

  router.get(
    "/setup2fa",
    authHandler.generateTwoFactorAuthenticationCode,
    function (req, res) {
      res.render("setup2fa", {
        login: req.user.login,
        qrCodeURL: req.qrCodeURL,
      });
    }
  );

  router.post(
    "/setup2fa",
    authHandler.turnOnTwoFactorAuthentication,
    function (req, res) {
      req.flash(
        "User successfully registered with 2fa. You will be redirected to the login page"
      );
      res.redirect("/learn");
    }
  );

  router.get("/auth2fa", authHandler.isAuthenticated, function (req, res) {
    if (!req.user.isTwoFactorAuthenticationEnabled) {
      req.flash(
        "danger",
        `Two Factor Authentication not enabled for user ${user.name}`
      );
      res.redirect("/login");
    }

    res.render("auth2fa");
  });

  router.post(
    "/auth2fa",
    authHandler.isAuthenticated,
    passport.authenticate("totp", {
      failureRedirect: "/login",
    }),
    function (req, res) {
      req.session.method = "totp";
      req.session.passedTotp = true;
      res.redirect("/learn");
    }
  );

  // utility routes for testing 2fa
  router.post("/2fa/generate", authHandler.generateTwoFactorAuthenticationCode);

  router.post("/2fa/turn-on", authHandler.turnOnTwoFactorAuthentication);

  return router;
};
