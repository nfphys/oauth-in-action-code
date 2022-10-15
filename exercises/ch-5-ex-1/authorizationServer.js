var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

  /*
   * Enter client information here
   */

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
	}
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
	/*
	 * Process the request, validate the client, and send the user to the approval page
	 */
	
	const client = getClient(req.query.client_id);
	if (!client) {
		res.render('error', { error: 'Unknown client' });
		return;
	}
	if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		res.render('error', { error: 'Invalid redirect URI' });
		return;
	}

	const reqid = randomstring.generate(8);
	requests[reqid] = req.query;

	res.render('approve', { client: client, reqid: reqid });
});

app.post('/approve', function(req, res) {

	/*
	 * Process the results of the approval page, authorize the client
	 */
	
	const reqid = req.body.reqid;
	const query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		res.render('error', { error: 'No matching authorization request' });
		return;
	}

	// 承認されなかった場合の処理
	if (!req.body.approve) {
		const urlParsed = buildUrl(query.redirect_uri, {
			error: 'access denied'
		});
		res.redirect(urlParsed);
		return;
	}

	// response_type が code でなかった場合の処理
	if (query.response_type !== 'code') {
		const urlParsed = buildUrl(query.redirect_uri, {
			error: 'unsupported response type'
		});
		res.redirect(urlParsed);
		return;
	}

	// authorization code を発行
	const code = randomstring.generate(8);
	codes[code] = { request: query };

	// クライアントにリダイレクト
	const urlParsed = buildUrl(query.redirect_uri, {
		code: code, 
		state: query.state,
	});
	res.redirect(urlParsed);
	return;
});

app.post("/token", function(req, res){

	/*
	 * Process the request, issue an access token
	 */

	let clientCredentials;
	let clientId;
	let clientSecret;

	// ヘッダに clientCredentials が含まれるかどうかを検証
	console.log("checking request header...");
	const auth = req.headers['authorization'];
	if (auth) {
		clientCredentials = decodeClientCredentials(auth);
		clientId = clientCredentials.id;
		clientSecret = clientCredentials.secret;
	}

	// ボディに clientCredentials が含まれるかどうかを検証
	console.log("checking request body...");
	if (req.body.client_id) {
		if (clientId) {
			// ヘッダとボディの両方に clientCredentials が存在すればエラーを返す
			res.status(401).json({error: 'Invalid_client'});
			return;
		}
		clientId = req.body.client_id;
		clientSecret = req.body.client_secret;
	}

	// clientCredentials が正しいかどうかを検証
	console.log("verifying client credentials...");
	const client = getClient(clientId);
	if (!client || client.client_secret != clientSecret) {
		res.status(401).json({error:'invalid_client'});
		return;
	}

	if (req.body.grant_type === 'authorization_code') {
		const code = codes[req.body.code];

		// code が存在するかどうかを検証
		if (!code) {
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
		delete codes[req.body.code];

		// code が正当なクライアントのものであるかどうかを検証
		if (code.request.client_id !== clientId) {
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
		delete codes[req.body.code];

		// アクセストークンを生成
		console.log("generating access_token...");
		const access_token = randomstring.generate();
		const expires_at = Date.now() + 5000;
		nosql.insert({
			access_token: access_token, 
			client_id: clientId,
			expires_at: expires_at,
		});

		const token_response = {
			access_token: access_token,
			token_type: 'Bearer'
		};
		res.status(200).json(token_response);

	} else {
		res.status(400).json({error: 'unsupported grant_type'});
		return;
	}



});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
