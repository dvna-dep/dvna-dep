var db = require("../models");
var bCrypt = require("bcrypt");
const exec = require("child_process").exec;
const execFile = require("child_process").execFile;
var mathjs = require("mathjs");
var libxmljs = require("libxmljs");
var serialize = require("node-serialize");
var vh = require("./validationHandler");

const Op = db.Sequelize.Op;

const pwLength = "- Must contain at least 8 characters<br>";
const pwLower = "- Must contain at least 1 lowercase letter<br>";
const pwUpper = "- Must contain at least 1 uppercase letter<br>";
const pwNumber = "- Must contain at least 1 number<br>";
const pwSpec = "- Must contain at least 1 special character";
const badPWmsg =
  "Bad Password:<br>" + pwLength + pwLower + pwUpper + pwNumber + pwSpec;

module.exports.userSearch = function (req, res) {

  if (req.body.securityRating == '0') {
    var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
    db.sequelize.query(query, {
      model: db.User
    }).then(user => {
      if (user.length) {
        var output = {
          user: {
            name: user[0].name,
            id: user[0].id
          }
        }
        res.render('app/usersearch', {
          securityRating: req.body.securityRating,
          output: output
        })
      } else {
        req.flash('warning', 'User not found')
        res.render('app/usersearch', {
          securityRating: req.body.securityRating,
          output: null
        })
      }
    }).catch(err => {
      req.flash('danger', 'Internal Error')
      res.render('app/usersearch', {
        securityRating: req.body.securityRating,
        output: null
      })
    })
  } else if (req.body.securityRating == '1') {
    // check input for allowed characters
    if (vh.vWhitelist(req.body.login)) {
      db.User.find({
        where: { 'login': req.body.login }
      }).then(user => {
        if (user) {
          var output = {
            user: {
              name: user.name,
              id: user.id
            }
          }
          res.render('app/usersearch', {
            securityRating: req.body.securityRating,
            output: output
          })
        } else {
          req.flash('warning', 'User not found')
          res.render('app/usersearch', {
            securityRating: req.body.securityRating,
            output: null
          })
        }
      }).catch(err => {
        req.flash('danger', 'Internal Error')
        res.render('app/usersearch', {
          securityRating: req.body.securityRating,
          output: null
        })
      })
    } else {
      req.flash('danger', 'Invalid login ');
      req.flash('danger', 'Input Validation Failed');
      res.render('app/usersearch', {
        securityRating: req.body.securityRating,
        output: null
      })
    }
  }

}

module.exports.ping = function (req, res) {
  if (req.body.securityRating == '0') {
    exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
      output = stdout + stderr
      res.render('app/ping', {
        securityRating: req.body.securityRating,
        output: output
      })
    })
  } else if (req.body.securityRating == '1') {
    // check if input is a valid IP address or URL
    if (vh.vIP(req.body.address) || vh.vUrl(req.body.address)) {
      execFile('ping', ['-c', '2', req.body.address], function (err, stdout, stderr) {
        output = stdout + stderr
        res.render('app/ping', {
          securityRating: req.body.securityRating,
          output: output
        })
      })
    } else {
      res.render('app/ping', {
        securityRating: req.body.securityRating,
        output: "Input Validation Failed"
      })
    }


  }
}

module.exports.listProducts = function (req, res) {
  db.Product.findAll().then((products) => {
    output = {
      products: products,
    };
    res.render("app/products", {
      output: output,
    });
  });
};

module.exports.productSearch = function (req, res) {
  db.Product.findAll({
    where: {
      name: {
        [Op.like]: "%" + req.body.name + "%",
      },
    },
  }).then((products) => {
    output = {
      products: products,
      searchTerm: req.body.name,
    };
    res.render("app/products", {
      output: output,
    });
  });
};

module.exports.modifyProduct = function (req, res) {
  if (!req.query.id || req.query.id == "") {
    output = {
      product: {},
    };
    res.render("app/modifyproduct", {
      output: output,
    });
  } else {
    db.Product.find({
      where: {
        id: req.query.id,
      },
    }).then((product) => {
      if (!product) {
        product = {};
      }
      output = {
        product: product,
      };
      res.render("app/modifyproduct", {
        output: output,
      });
    });
  }
};

module.exports.modifyProductSubmit = function (req, res) {
  if (!req.body.id || req.body.id == '') {
    req.body.id = 0
  }
  db.Product.find({
    where: {
      'id': req.body.id
    }
  }).then(product => {
    if (!product) {
      product = new db.Product()
    }
    product.code = req.body.code
    product.name = req.body.name
    product.description = req.body.description
    product.tags = req.body.tags
    product.save().then(p => {
      if (p) {
        req.flash('success', 'Product added/modified!')
        res.redirect('/app/products')
      }
    }).catch(err => {
      output = {
        product: product
      }
      req.flash('danger', err)
      res.render('app/modifyproduct', {
        output: output
      })
    })
  })
}

module.exports.userEdit = function (req, res) {
  res.render("app/useredit", {
    vuln5: "a5_broken_access_control",
    vuln2: "a2_broken_auth",
    a5securityRating: req.session.ratingState["a5_broken_access_control"],
    a2securityRating: req.session.ratingState["a2_broken_auth"],
    userId: req.user.id,
    userEmail: req.user.email,
    userName: req.user.name,
  });
};

module.exports.userEditSubmit = function (req, res) {
  userEditSubmitCheckA5SecurityRating(req, res);
};

function userEditSubmitCheckA5SecurityRating(req, res) {
  if (req.session.ratingState["a5_broken_access_control"] == 0)
    editUserInfo(req, res);
  else editUserInfoSecurely(req, res);
}

function editUserInfoSecurely(req, res) {
  if (req.user.id == req.body.id) {
    editUserInfo(req, res);
  } else {
    userEditMSGandRender(
      req,
      res,
      true,
      "warning",
      "Invalid Request to Edit User Data"
    );
  }
  return;
}

function editUserInfo(req, res) {
  db.User.find({
    where: {
      id: req.body.id,
    },
  }).then((user) => {
    validateUserInfo(user, req, res);
  });
}

function validateUserInfo(user, req, res) {
  if (req.session.ratingState["a2_broken_auth"] == 0)
    changeUserInfoWithoutValidation(user, req, res);
  else changeUserInfoWithValidation(user, req, res);
}

function changeUserInfoWithoutValidation(user, req, res) {
  if (req.body.password.length > 0) changePW(user, req, res);
  user.name = req.body.name;
  user.email = req.body.email;
  user.save().then(function () {
    userEditMSGandRender(req, res, true, "success", "Updated successfully");
  });
}

function changeUserInfoWithValidation(user, req, res) {
  if (req.body.password.length > 0) {
    if (vh.vPassword(req.body.password)) {
      changePW(user, req, res);
    } else {
      userEditMSGandRender(req, res, true, "warning", badPWmsg);
      return;
    }
  }
  user.name =
    req.body.name.length > 0
      ? (user.name = req.body.name)
      : (user.name = user.name);
  if (req.body.email.length > 0) {
    if (vh.vEmail(req.body.email)) {
      user.email = req.body.email;
    } else {
      userEditMSGandRender(req, res, true, "warning", "Invalid Email");
      return;
    }
  } else {
    user.name = user.name;
  }
  user.save().then(function () {
    userEditMSGandRender(req, res, true, "success", "Updated successfully");
  });
}

function changePW(user, req, res) {
  if (req.body.password.length > 0) {
    if (req.body.password == req.body.cpassword) {
      user.password = bCrypt.hashSync(
        req.body.password,
        bCrypt.genSaltSync(10),
        null
      );
    } else {
      userEditMSGandRender(req, res, true, "warning", "Passwords dont match");
      return;
    }
  } else {
    userEditMSGandRender(req, res, true, "warning", "Invalid Password");
    return;
  }
}

function userEditMSGandRender(req, res, flashBool, flashType, flashMSG) {
  if (flashBool == true) {
    req.flash(flashType, flashMSG);
  }
  res.render("app/useredit", {
    vuln5: "a5_broken_access_control",
    vuln2: "a2_broken_auth",
    a5securityRating: req.session.ratingState["a5_broken_access_control"],
    a2securityRating: req.session.ratingState["a2_broken_auth"],
    userId: req.body.id,
    userEmail: req.body.email,
    userName: req.body.name,
  });
}

module.exports.redirect = function (req, res) {
  if (req.query.url) {
    res.redirect(req.query.url);
  } else {
    res.send("invalid redirect url");
  }
};

// A6 Security Misconfiguration
module.exports.calc = function (req, res) {
  if (ratingState['a6_sec_misconf'] == 0) {
    calcRating0(req, res);
  } else {
    calcRating1(req, res)
  }
}

function calcRating0(req, res) {
  if (req.body.eqn) {
    res.render('app/calc', {
      output: mathjs.eval(req.body.eqn)
    })
  } else {
    res.render('app/calc', {
      output: 'Enter a valid math string like (3+3)*2'
    })
  }
}

function calcRating1(req, res) {
  if (req.body.eqn) {
    try {
      result = mathjs.eval(req.body.eqn)
    } catch (err) {
      result = 'Invalid Equation'
    };
    res.render('app/calc', {
      output: result
    })
  } else {
    res.render('app/calc', {
      output: 'Enter a valid math string like (3+3)*2'
    })
  }
}


// --- A3 Sensitive Data Exposure ---
function listUsersAPIRating0(res) {
  return db.User.findAll({}).then(users => {
    res.status(200).json({
      success: true,
      users: users
    })
  })
}
function listUsersAPIRating1(res) {
  return db.User.findAll({ attributes: ['id', 'name', 'email'] },)
    .then(users => {
      res.status(200).json({
        success: true,
        users: users
      })
    });
}

module.exports.listUsersAPI = function (req, res) {
  var vulnKey = 'a3_sensitive_data';
  securityRating = ratingState[vulnKey]
  if (securityRating == 0) {
    listUsersAPIRating0(res);
  } else if (securityRating == 1) {
    listUsersAPIRating1(res);
  };
}

module.exports.bulkProductsLegacy = function (req, res) {
  // TODO: Deprecate this soon
  if (req.files.products) {
    var products = serialize.unserialize(req.files.products.data.toString('utf8'))
    products.forEach(function (product) {
      var newProduct = new db.Product()
      newProduct.name = product.name
      newProduct.code = product.code
      newProduct.tags = product.tags
      newProduct.description = product.description
      newProduct.save()
    })
    res.redirect('/app/products')
  } else {
    res.render('app/bulkproducts', { messages: { danger: 'Invalid file' }, legacy: true })
  }
}

module.exports.bulkProducts = function (req, res) {
  if (req.files.products && req.files.products.mimetype == 'text/xml') {
    var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), { noent: true, noblanks: true })
    products.root().childNodes().forEach(product => {
      var newProduct = new db.Product()
      newProduct.name = product.childNodes()[0].text()
      newProduct.code = product.childNodes()[1].text()
      newProduct.tags = product.childNodes()[2].text()
      newProduct.description = product.childNodes()[3].text()
      newProduct.save()
    })
    res.redirect('/app/products')
  } else {
    res.render('app/bulkproducts', { messages: { danger: 'Invalid file' }, legacy: false })
  }
}
