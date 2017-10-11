// Server for Simple Work Queue System
const cluster = require('cluster');
const express = require("express");
const expressSession = require("express-session");
const expressHantweb2 = require("express-hantweb2");
const bodyParser = require("body-parser");
const fs = require("fs");
const cors= require('cors')
const http = require('http');
const HttpStatus = require('http-status-codes');
const jwt = require('express-jwt');
const jsonwebtoken = require("jsonwebtoken");
const path = require('path');

const config = require('./config');
const logger = config.LOGGER

// load routes
const originatorApiRouter = require('./routes/originator')
const consumerApiRouter = require('./routes/consumer')
const itemApiRouter = require('./routes/item')

const expressApp = express();
expressApp.use(cors());

// ===== GENERAL API ROUTER ===================================================
const generalApiRouter = express.Router();

// Make sure we can parse the posted JSON content:
generalApiRouter.use(bodyParser.json())
var publicKey = config.publicKey

generalApiRouter.use(jwt({
  secret: publicKey,
  credentialsRequired: false
}));

// Diagnostics
generalApiRouter.all("/*",(req,res,next) => {
  logger.info("GENERAL API HIT: ",req.url);
  next();
});

// Generic diagnostic URL
generalApiRouter.get('/ping',function(req,res) {
  logger.info("Ping User (optional): ",req.user);
  res.status(HttpStatus.OK).send({ msg: "OK"}).end();
});

generalApiRouter.post('/echo',function(req,res) {
  var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  logger.info("Authorization: " + req.headers["authorization"]);
  res.status(HttpStatus.OK).end();
});

// no authentication needed for swagger ui to read api-docs.json
generalApiRouter.get('/api-docs',function(req,res) {
  logger.info("REQUEST FOR SWAGGER API DOC");
  var options = {
    root: path.resolve(__dirname, '..', 'dist')
  }
  res.sendFile('api-docs.json', options);
});

// ====== UI ROUTER ===========================================================
const uiRouter = express.Router();

// Make sure we have express-session enabled:
uiRouter.use(expressSession({
  secret: 'secret234',
  resave: false,
  saveUninitialized: true
}));

// Plug in the Hantweb2 middleware
if (config.SSL =='true')
	uiRouter.use(expressHantweb2.authenticate(expressHantweb2.env.PROD));
else
	uiRouter.use(expressHantweb2.authenticate(expressHantweb2.env.STAGE));

uiRouter.all("/*",(req,res,next) => {
  logger.info("UI API HIT: ",req.url);
  next();
});

// A function that allows a user to trade in their HANTWEB2 claims for a
// JWT token that can be used with the consumer API
uiRouter.get('/doauth',function(req,res) {
  logger.info("In doauth");
  if (!req.session || !req.session.jwtClaims) {
    res.status(HttpStatus.FORBIDDEN).send("Unauthorized").end();
    return;
  }
  logger.info("Authentication call received for: " + req.session.jwtClaims.sub);
  // Private key needed for authentication
  const privateKey = fs.readFileSync('./keys/private');
  // Create the JWT token - will be sent to the UI to identify the user
  const jwtToken = jsonwebtoken.sign( { id: req.session.jwtClaims.sub },
    privateKey, { algorithm: 'RS256'});

  res.status(HttpStatus.OK).send({
    token: jwtToken,
    swqsUrl: config.SWQS_REST_URL
  }).end();
});

// Swagger ui
uiRouter.use("/swagger-ui", express.static("swagger-ui"));
uiRouter.use("/", express.static("swagger-ui"));

// ===== TOP-LEVEL SERVER =====================================================
expressApp.use(`${config.VERSION_BASE}/originator`,originatorApiRouter);
expressApp.use(`${config.VERSION_BASE}/consumer`, consumerApiRouter);
expressApp.use(`${config.VERSION_BASE}`,generalApiRouter);
expressApp.use("/",uiRouter);
// will handle item requests - such as attachments
expressApp.use('/item', itemApiRouter);
// will handle actions taken by the consumer via the notification
expressApp.use('/notification', consumerApiRouter);

// Start the server listening:
const numCPUs = require('os').cpus().length;
if (cluster.isMaster) {
  logger.info(`Master ${process.pid} is running`);

  // Fork workers.
  for (var i = 0; i < numCPUs; i++) {
  // TEMP - having issues with multiple webhooks firing with multiple process
  // fix that prior to running multiple workers
  // for (var i = 0; i < 1; i++) {
    var worker = cluster.fork();
 

 worker.on('message', function(message) {
    console.log(message);
	worker.send('hello from the master');
expressApp.use(`${config.VERSION_BASE}/originator`,originatorApiRouter);
expressApp.use(`${config.VERSION_BASE}/consumer`, consumerApiRouter);
expressApp.use(`${config.VERSION_BASE}`,generalApiRouter);
expressApp.use("/",uiRouter);
// will handle item requests - such as attachments
expressApp.use('/item', itemApiRouter);
// will handle actions taken by the consumer via the notification
expressApp.use('/notification', consumerApiRouter);
});
 }  
  cluster.on('exit', (worker, code, signal) => {
    // Log the event and restart
    logger.error('Worker %d died (%s). restarting...',
                worker.process.pid, signal || code);
    cluster.fork();
  });
  
}
else {
	process.on('message', function(message) {
    console.log(message);
	process.send('hello from worker with id: ' + process.pid);
});
}
 else {
  // Workers can share any TCP connection
  // In this case it is an HTTP server
  expressApp.listen(config.LISTEN_PORT,function(err) {
    if (err) {
      logger.error("Failed to listen");
      return;
    }
    logger.info(`Simple Work Queue Server (Worker: ${process.pid}) listening on ${config.LISTEN_PORT}`);
  });
}
