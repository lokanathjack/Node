var cluster = require('cluster');
var http = require('http');
var numReqs = 0;
var workers = [];
const numCPUs = require('os').cpus().length;
if (cluster.isMaster) {
  // Broadcast a message to all workers
  var broadcast = function() {
    for (var i in workers) {
      var worker = workers[i];
      worker.send({ cmd: 'broadcast', numReqs: numReqs });
    }
  }

  // Fork workers.
  for (var i = 0; i < numCPUs; i++) {
    var worker = cluster.fork();

    worker.on('message', function(msg) {
      if (msg.cmd) {
        switch (msg.cmd) {
          case 'notifyRequest':
            numReqs++;
          break;
          case 'broadcast':
            broadcast();
          break;
        }
	  }
    });

    // Add the worker to an array of known workers
    workers.push(worker);
  }

  setInterval(function() {
    console.log("numReqs =", numReqs);
  }, 1000);
} else {
  // React to messages received from master
  process.on('message', function(msg) {
    switch(msg.cmd) {
      case 'broadcast':
        if (msg.numReqs) console.log('Number of requests: ' + msg.numReqs);
      break;
    }
  });

  // Worker processes have a http server.
  http.Server(function(req, res) {
    res.writeHead(200);
    res.end("hello world\n");
    // Send message to master process
    process.send({ cmd: 'notifyRequest' });
    process.send({ cmd: 'broadcast' });
  }).listen(8000);
}