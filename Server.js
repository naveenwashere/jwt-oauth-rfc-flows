var express = require('express');
var bodyParser = require('body-parser');
var mongoOp = require('./models/mongo');
var {signAndEncrypt, decryptAndVerify} = require('./services/jwt.service');

const app = express();
const router = express.Router();

//Ideally these parameters should be gathered by FE and passed along!
const deviceId = 'Android'; //to be collected by FE
const isLoggedIn = 0; //default 0 unless sepecified by incoming JWT
const isRevoked = 0; //default 0 unless specified by blaclist
const deviceType = 'Mobile'; //to be collected by FE
const ipAddress = '192.168.1.1'; //to be collected by FE

const issuedAt = new Date().getTime() / 1000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({"extended": false}));

router.get("/", function (req, res) {
  res.json({"error": false, "message": "Hello World. Lets implement JWT!"});
});

router.route("/users")
  .get(function (req, res) {
    var response = {};
    mongoOp.find({}, function (err, data) {
      if (err) {
        response = {"error": true, "message": "Error fetching data"};
      } else {
        response = {"error": false, "message": data};
      }
      res.json(response);
    });
  });

router.route("/users/:id")
  .get(function (req, res) {
    let response = {};
    mongoOp.findById(req.params.id, function (err, data) {
      if (err) {
        response = {"error": true, "message": "Error fetching data"};
      } else {
        response = {"error": false, "message": data};
      }
      res.json(response);
    });
  })
  .delete(function (req, res) {
    let response = {};
    mongoOp.findById(req.params.id, function (err, data) {
      if (err) {
        response = {"error": true, "message": "Error fetching data"};
      } else {
        mongoOp.remove({_id: req.params.id}, function (err) {
          if (err) {
            response = {"error": true, "message": "Error deleting data"};
          } else {
            response = {"error": true, "message": "Data associated with " + req.params.id + "is deleted"};
          }
          res.json(response);
        });
      }
    });
  });

function addAdditionalParamsForAccessTokenGen(response, isLoggedIn) {
  response['deviceId'] = deviceId;
  response['deviceType'] = deviceType;
  response['isLoggedIn'] = isLoggedIn;
  response['isRevoked'] = isRevoked;
  response['ipAddress'] = ipAddress;
  return response;
}

router.route("/access_token/:id")
  .get(function (req, res) {
    let response = {};
    let refreshTokenPayload = {};
    mongoOp.findById(req.params.id, function (err, data) {
      if (err) {
        response = {"error": true, "message": "Error fetching data"};
      } else {
        response = data.toObject();
      }
      console.log('User data retrieved from DB:\n');
      console.log(response);
      response = addAdditionalParamsForAccessTokenGen(response, 1);
      refreshTokenPayload = generatePayloadForRefreshTokenGen(response, 0);
      console.log('User data retrieved from DB and additional data added:\n');
      console.log(response);
      signAndEncrypt(response, 'access_token')
        .then(actoken => {
          let access_token = actoken;
          signAndEncrypt(refreshTokenPayload, 'refresh_token')
            .then(rftoken => {
              res.send({
                'access_token': access_token,
                'refresh_token': rftoken
              });
            })
            .catch(error => {
              return res.send({
                error: true,
                message: 'Something went wrong while generating refresh token: ' + error.message
              })
            })
        })
        .catch(error => {
          return res.json({
            error: true,
            message: 'Something went wrong while generating access/refresh token: ' + error.message
          })
        });
    });
  });

function generatePayloadForRefreshTokenGen(response, revoke) {
  let accessTokenObject = {};
  accessTokenObject['accessTokenId'] = response.uuid + '.' + response.username + '.' + deviceId + '.' + deviceType;
  accessTokenObject['isRevoked'] = revoke;
  return accessTokenObject;
}

//Do we need to invalidate and send the old token back? I guess no need since it expires in 15 mins
//Should update issuedAt for refresh token??? Explore! RFC?
router.route("/refresh_token")
  .post(function (req, res) {
    let response = {};
    let refreshToken = req.body.refreshToken;
    decryptAndVerify(refreshToken)
      .then(validatedRes => {
        if (validatedRes.isValid) {
          if(validatedRes.nakedToken.isRevoked === 1) {
            return res.json({
              error: true,
              message: 'Invalid refresh token. This token has been revoked. Initiate security check! Whoooop whooop whooop!'
            });
          }
          mongoOp.findById(req.body.id, function (err, data) {
            if (err) {
              response = {
                "error": true,
                "message": "Error fetching data"
              };
              return res.json(response);
            } else {
              response = data.toObject();
            }
            response = addAdditionalParamsForAccessTokenGen(response, 1);
            signAndEncrypt(response, 'access_token')
              .then(actoken => {
                return res.json({
                    'access_token': actoken,
                    'refresh_token': refreshToken
                  })
                }
              )
              .catch(error => {
                return res.json({
                  error: true,
                  message: 'Something went wrong while refreshing access token: ' + error.message
                })
              })
          });
        } else {
          return res.json({error: true, message: 'Incorrect/Invalid refresh token'});
        }
      })
      .catch(error => {
        return res.json({
          error: true,
          message: 'Something went wrong while verifying the refresh token: ' + error.message
        })
      })
  });

router.route("/revoke_refresh_token")
  .post(function (req, res) {
    let response = {};
    let refreshToken = req.body.refreshToken;
    decryptAndVerify(refreshToken)
      .then(validatedRes => {
        if (validatedRes.isValid) {
          if(validatedRes.nakedToken.isRevoked === 1) {
            return res.json({
              error: true,
              message: 'Invalid refresh token. This token has been revoked. Initiate security check! Whoooop whooop whooop!'
            });
          }
          mongoOp.findById(req.body.id, function (err, data) {
            if (err) {
              response = {
                "error": true,
                "message": "Error fetching data"
              };
              return res.json(response);
            } else {
              response = data.toObject();
            }
            response = generatePayloadForRefreshTokenGen(response, 1);
            signAndEncrypt(response, 'refresh_token')
              .then(rftoken => {
                  return res.json({
                    'refresh_token': rftoken
                  })
                }
              )
              .catch(error => {
                return res.json({
                  error: true,
                  message: 'Something went wrong while revoking refreshing token: ' + error.message
                })
              })
          });
        } else {
          return res.json({error: true, message: 'Incorrect/Invalid refresh token. So, never mind!'});
        }
      })
      .catch(error => {
        return res.json({
          error: true,
          message: 'Something went wrong while verifying the refresh token: ' + error.message
        })
      })
  });

//Find out how its usuall done.
//For now, just set the isLoggedIn flag to false in the access token
router.route("/logout")
  .post(function (req, res) {
    let response = {};
    let accessToken = req.body.accessToken;
    decryptAndVerify(accessToken, 'access_token')
      .then(validatedRes => {
        if (validatedRes.isValid) {
          if(validatedRes.nakedToken.isLoggedIn === 0) {
            return res.json({
              error: true,
              message: 'Already logged out. Why try again?'
            });
          }
          response = addAdditionalParamsForAccessTokenGen(validatedRes.nakedToken, 0);
          signAndEncrypt(response, 'access_token')
            .then(actoken => {
                return res.json({
                  'access_token': actoken
                })
              }
            )
            .catch(error => {
              return res.json({
                error: true,
                message: 'Something went wrong while logging out of access token: ' + error.message
              })
            });
        } else {
          return res.json({error: true, message: 'Incorrect/Invalid access token.'});
        }
      })
      .catch(error => {
        return res.json({
          error: true,
          message: 'Something went wrong while verifying the access token: ' + error.message
        })
      })
  });

app.use('/', router);

app.listen(3000);
console.log("Listening to PORT 3000");
