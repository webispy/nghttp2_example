const port = 3000
const http2 = require('http2')
const fs = require('fs')

const options = {
  key: fs.readFileSync(__dirname + '/server.key'),
  cert:  fs.readFileSync(__dirname + '/server.crt'),
}

console.log(options)

var server = http2.createServer(options, function(req, res) {
  console.log('url is', req.url);

  if (req.url === '/push') {
    console.log('make half-closed state');

    var push = res.push('/main.js', {
      method: 'GET',
    })

    push.on('error', function() { console.log('error') })
    push.writeHead(200)

    setInterval(function () {
      push.write('haha')
      push.write('hoho')
    }, 2000)

  } else {
    console.log('send 1 line response');
    res.writeHead(200);
    res.end('<script src="/main.js"></script>hello world!');
  }
});

server.listen(3000, function() {
  console.log(server)
});

