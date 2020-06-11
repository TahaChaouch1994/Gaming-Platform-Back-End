var MongoClient = require('mongodb').MongoClient;
var {ObjectId} = require('mongodb');
var express = require('express');
var http = require('http');
var bodyParser = require('body-parser');
var nodemailer = require('nodemailer');
var randomize = require('randomatic');
var Web3 = require("web3");
var multer = require('multer');
var fs = require('fs');
var SteamAPI = require('steamapi');
const Tx = require('ethereumjs-tx').Transaction;
var passport = require('passport')
var util = require('util')
var session = require('express-session')
var SteamStrategy = require('passport-steam').Strategy;
var CryptoJS = require("crypto-js");
var formidable = require('formidable');
var CodeGenerator = require('node-code-generator');
var queue = require("queue");
var path = require('path');
var cors = require('cors');

var generator = new CodeGenerator();
var pattern = 'TRN##########+';
var howMany = 1;
var options = {};

const web3 = new Web3(new Web3.providers.HttpProvider("https://rinkeby.infura.io/v3/8d711d11e56847bd936f08dba7658286"))
//var url = "mongodb://samer1:samroot123@localhost:27017/geeks";
var url = "mongodb://localhost:27017/geeks";

let abi = JSON.parse(fs.readFileSync('abi.json', 'utf8'));
let tokenAddress = "0xbb67E0fF9AF8e5EFa44EA46ca51aB257dDcAa87F";
let contract = new web3.eth.Contract(abi, tokenAddress);
var _database;

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

passport.use(new SteamStrategy({
    returnURL: 'http://localhost:1337/auth/steam/return',
    realm: 'http://localhost:1337/',
    apiKey: '3D8418EE8F1B7111B45A8BEB4F4D5610'
  },
  function(identifier, profile, done) {
    process.nextTick(function () {
      profile.identifier = identifier;
      return done(null, profile);
    });
  }
));

var app = express();
var checkoutArray = [];
server = http.createServer(app);
var io = require('socket.io').listen(server);
const steam = new SteamAPI('3D8418EE8F1B7111B45A8BEB4F4D5610');

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'geeksoverflow@gmail.com',
    pass: 'samroot123'
  }
});


// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());

app.use('/avatars', express.static('avatars'));
app.use('/user_merch', express.static('user_merch'));
app.use('/thread_attachements', express.static('thread_attachements'));

app.use(cors());


app.use(function(req, res, next) 
{
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "*");
  res.header("Access-Control-Allow-Methods", "*");
  res.header('Access-Control-Allow-Credentials', true);
  next();
});
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(__dirname + '/../../public'));

app.use(session({
    secret: 'geekssecretsteam',
    name: 'name of session id',
    resave: true,
    saveUninitialized: true}));




MongoClient.connect(url, {useNewUrlParser: true, useUnifiedTopology: true}, function(err, db) {
  if (err) throw err;
  console.log("Connected");
  _database = db;
});


function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/steam');
}

function verifyUserEmailUsernameUnicity(email, username, cb)
{
	var dbo = _database.db("geeks");
	var query = {$or:[{"username":username}, {"email":email}]};
	
	dbo.collection("user").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		cb(result);
	});
}

function sendVerificationEmail(id, email)
{
	let randomCode = randomize('0', 5);
	
	var dbo = _database.db("geeks");
	var myobj = { user: id, code: randomCode };
	dbo.collection("verification_keys").insertOne(myobj, function(err, res) {
		if (err) throw err;
	});
	
	var mailOptions = {
		from: 'geeksoverflow@gmail.com',
		to: email,
		subject: '[GeeksOverflow] Account Verification',
		html: "<p>Welcome to GeeksOverflow! You can verify your account following this link: http://localhost:4200/verifyUser?id="+id+"&key="+randomCode+"</p>"
	};
	transporter.sendMail(mailOptions, function(error, info)
	{
		if (error) 
		{
		console.log(error);
		} 
		else 
		{
			console.log('Email sent: ' + info.response);
		}
	}); 
}

function verifyUserKey(id, key, cb)
{
	var dbo = _database.db("geeks");
	var query = { user: ObjectId(id), code: key };
	dbo.collection("verification_keys").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		cb(result);
	});
}

function getUserFromId(id, callback)
{
	var dbo = _database.db("geeks");
	dbo.collection("user").findOne({'_id': ObjectId(id)}, function(err, result) 
	{
		if (err) throw err;
		callback(result);
	});
}

function hasWallet(id, cb)
{
	var dbo = _database.db("geeks");
	var query = { user: id };
	dbo.collection("wallets").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		cb(result);
	});
}

async function getMerchFromId(idMerch, callback)
{
	var dbo = _database.db("geeks");
	dbo.collection("user_merch").findOne({'_id': idMerch}, function(err, result) 
	{
		if (err) throw err;
		callback(result);
	});
}

var incrementNonce = 0;

function transferTokens(adrFrom, adrTo, privateKey, amount)
{
	let obj = {"adrFrom": adrFrom, "adrTo": adrTo, "privateKey": privateKey, "amount": amount};
	checkoutArray.push(obj);
}

setInterval(function()
{
	if ((checkoutArray[0] == null) || (checkoutArray[0] == undefined))
	{
		//console.log("Empty payment queue");
	}
	else
	{
		let obj = checkoutArray[0];
		checkoutArray.splice(0, 1);
		let privateKeyBuffer = Buffer.from(obj.privateKey, 'hex')
	
		web3.eth.getTransactionCount(obj.adrFrom)
		.then((count) => 
		{		
			let rawTransaction= {
				'from': obj.adrFrom,
				'gasPrice': web3.utils.toHex(20 * 1e9),
				'gasLimit': web3.utils.toHex(210000),
				'to':tokenAddress,
				'value': 0x0,
				'data': contract.methods.transfer(obj.adrTo, obj.amount).encodeABI(),
				'nonce': web3.utils.toHex(count) 
			};    
			
			let transaction = new Tx(rawTransaction, {'chain':'rinkeby'});
			incrementNonce++;
			transaction.sign(privateKeyBuffer);
			web3.eth.sendSignedTransaction('0x' + transaction.serialize().toString('hex')).on('receipt', console.log)
		});
	}
//}, 60000*2);
}, 1000*30);

app.post("/user/register", function(req, res)
{
	console.log(req.body)
	var dbo = _database.db("geeks");
	let email = req.body.email;
	let username = req.body.username;
	let password = req.body.password;
	let dob = req.body.dob;
	let role = req.body.role;
	let status = req.body.status;
	var firstName, lastName;
	if (req.body.firstName != null)
	{
		firstName = req.body.firstName;
	}
	else
	{
		firstName = "";
	}
	if (req.body.lastName != null)
	{
		lastName = req.body.lastName;
	}
	else
	{
		lastName = "";
	}

	verifyUserEmailUsernameUnicity(email, username, 
		function(result)
		{
			console.log("Found " + result.length + " occurences with same username or email");
			if (result.length > 0)
			{
				res.json("Username or email already used.");
			}
			else
			{
				dbo.collection("user").insertOne(req.body, function(err, res2) 
				{
					if (err) throw err;
					console.log("inserted new document with id: "+req.body._id);
					sendVerificationEmail(req.body._id, email)
					res.json(req.body._id);
				});
			}
		});
});


app.get("/user/login", function(req, res)
{
	console.log("loggin");
	var dbo = _database.db("geeks");
	let login = req.query.login;
	let password = req.query.password;
	verifyUserEmailUsernameUnicity(login, login, function(result)
	{
		if (result.length == 0)
		{
			res.json("Account not found.");
		}
		else
		{
			if (password != result[0]["password"])
			{
				res.json("Wrong password.");
			}
			else
			{
				res.json(result[0]);
			}
		}
	});
});

app.put("/user/updateActivity", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let user_id = req.body.id_user;
	let status = req.body.status;
	let lastActive = req.body.lastActive;

	dbo.collection("user").updateOne({'_id': ObjectId(user_id)}, { $set: {lastActive: lastActive, activity: status } }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.put("/user/update", function(req, res)
{
	//req.body;
	let email = req.body.email;
	let username = req.body.username;
	let user_id = req.body.id_user;
	delete req.body.id_user;
	var dbo = _database.db("geeks");
	verifyUserEmailUsernameUnicity(email, username, function(result)
	{
		if (result.length > 0)
		{
			console.log("found occurence");
			if ((result[0]["email"] != email) && (result[0]["username"] != username))
			{
				res.json("Username or email already used.");
			}
			else
			{
				var myuser = {'_id': ObjectId(user_id)};
				dbo.collection("user").updateOne(myuser, { $set: req.body }, function(err, result2) 
				{
					if (err) throw err;
					console.log("1 document updated");
					res.json(user_id);
				});
			}
		}
		else
		{
			var myuser = {'_id': ObjectId(user_id)};
			dbo.collection("user").updateOne(myuser, { $set: req.body }, function(err, result2) 
			{
				if (err) throw err;
				console.log("1 document updated");
				res.json(user_id);
			});
		}
	}
	);
});

app.get("/user/verify", function(req, res)
{
	var dbo = _database.db("geeks");
	let id = req.query.id;
	//console.log(id);
	let key = req.query.key;
	verifyUserKey(id, key, function(result)
	{
		if (result.length > 0)
		{
			var mykey = {'_id': ObjectId(result[0]["_id"])};
			dbo.collection("verification_keys").deleteOne(mykey, function(err, obj) 
			{
				if (err) throw err;
			});
			dbo.collection("user").updateOne({'_id': ObjectId(id)}, { $set: {status: "activated" } }, function(err, result2) 
			{
				if (err) throw err;
			});
			let streamKey = randomize('Aa0!', 10);
			dbo.collection("stream_keys").insertOne({'user': ObjectId(id), 'streamKey': streamKey}, function(err, result) {
				if (err) throw err;
			});
			dbo.collection("friends").insertOne({'user': ObjectId(id), 'friends': []}, function(err, result) {
				if (err) throw err;
			});
			res.json("Success");
		}
		else
		{
			res.json("This code is invalid");
		};
	});
});

app.get("/user/find", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("user").findOne({'_id': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
		//console.log(result);
		res.json(result);
	});
});


app.get("/user/hasWallet", function(req, res)
{
	var dbo = _database.db("geeks");
	let id = req.query.id;
	hasWallet(id, function(result)
	{
		if (result.length > 0)
		{
			contract.methods.balanceOf(result[0]["adr"]).call((error, balance) => 
			{
				//console.log(balance.toString() + " ESD");
				res.json({"balance": balance.toString(), "adr": result[0]["adr"]});
			});
			
		}
		else
		{
			res.json("None");
		}
	});
});

app.post("/user/privateKeyToAccount", function(req, res)
{
	
	let user = req.body.user;
	let hashedKey = req.body.key;
	//console.log(hashedKey);
	var hashKey = '6IAVE+56U5t7USZhb+9wCcqrTyJHqAu09j0t6fBngNo=';
	var bytes  = CryptoJS.AES.decrypt(hashedKey, hashKey);
	var key = bytes.toString(CryptoJS.enc.Utf8);
	console.log(key);
	let info = web3.eth.accounts.privateKeyToAccount('0x'+key);
	console.log(info.address);
	var dbo = _database.db("geeks");
	
	var query = { adr: info.address };
	dbo.collection("wallets").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		if (result.length > 0)
		{
			res.json("Already used");
		}
	});
	
	var myobj = { user: user, adr: info.address };
	dbo.collection("wallets").insertOne(myobj, function(err, result) {
		if (err) throw err;
		res.json("fine");
	});
});

app.post("/user/createWallet", function(req, res)
{
	let user = req.body.user;
	console.log(req.body);
	let info = web3.eth.accounts.create();
	let hashKey = '6IAVE+56U5t7USZhb+9wCcqrTyJHqAu09j0t6fBngNo=';
	let ciphertext = CryptoJS.AES.encrypt(info.privateKey, hashKey).toString();
	console.log("original key: " + info.privateKey);
	console.log(ciphertext);
	var dbo = _database.db("geeks");
	var myobj = { user: user, adr: info.address };
	dbo.collection("wallets").insertOne(myobj, function(err, result) {
		if (err) throw err;
		/*var mailOptions = {
			from: 'geeksoverflow@gmail.com',
			to: email,
			subject: '[GeeksOverflow] Wallet Creation',
			html: "<p>Your wallet has been successfully created, you can find the information related to your wallet below:</p> <p>Public Address: "+info.address+"</p> <p>Private Key: "+info.privateKey+"</p>"
		};
		transporter.sendMail(mailOptions, function(error, info)
		{
			if (error) 
			{
			console.log(error);
			} 
			else 
			{
				console.log('Email sent: ' + info.response);
			}
		});*/
		//res.json("fine");
		
		res.json(ciphertext);
	});
});

app.delete("/user/unlinkAccount", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.query.user;
	var mykey = {'user': user};
	dbo.collection("wallets").deleteOne(mykey, function(err, obj) 
	{
		if (err) throw err;
		res.json("fine");
	});
});

app.get("/user/streamKey", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.query.user;
	
	let streamKey = randomize('*', 15);

	dbo.collection("stream_keys").findOne({'user': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.get("/user/userstreamKey", function(req, res)
{
	var dbo = _database.db("geeks");
	let key = req.query.key;
	

	dbo.collection("stream_keys").findOne({'streamKey': ObjectId(key)}, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
})

app.post("/user/resetStreamKey", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.body.user;
	
	let streamKey = randomize('Aa0!', 15);

	dbo.collection("stream_keys").updateOne({"user": ObjectId(user)}, { $set: { "streamKey" : streamKey } }, function(err, result) 
	{
		if (err) throw err;
		console.log("1 document updated");
		res.json(streamKey);
	});
});

app.get("/user/isStreamKeyValid", function(req, res)
{
	var dbo = _database.db("geeks");
	let key = req.query.key;
	
	console.log("finding key");
	
	dbo.collection("stream_keys").find({'streamKey': key}).toArray(function(err, result) 
	{
		if (err) throw err;
		if (result.length == 0)
		{
			res.json("empty");
		}
		res.json(result);
	});
});

app.get("/user/friendRequests", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let receiver = ObjectId(req.query.receiver);
	
	dbo.collection('friend_requests').aggregate([
	{ '$match': { 'receiver':  receiver } },
    { $lookup:
       {
         from: 'user',
         localField: 'sender',
         foreignField: '_id',
         as: 'senderDetail'
       }
     }
    ]).toArray(function(err, result) {
		res.json(result);
  });
});

app.post("/user/sendFriendRequest", function(req, res)
{
	var dbo = _database.db("geeks");
	let sender = req.body.sender;
	let receiver = req.body.receiver;
	
	req.body.sender = ObjectId(sender);
	req.body.receiver = ObjectId(receiver);
	
	dbo.collection("friend_requests").insertOne(req.body, function(err, result) 
	{
		if (err) throw err;
		res.json(req.body._id);
	});
});

app.delete("/user/revokeFriendRequest", function(req, res)
{
	let friendReq = req.query.id;
	
	var dbo = _database.db("geeks");
	dbo.collection("friend_requests").deleteOne({'_id': ObjectId(friendReq)}, function(err, obj) 
	{
		if (err) throw err;
		res.end();
	});
});

app.get("/user/hasRequestForReceiver", function(req, res)
{
	let sender = req.query.sender;
	let receiver = req.query.receiver;
	var dbo = _database.db("geeks");
	dbo.collection("friend_requests").find({ sender: ObjectId(sender), receiver: ObjectId(receiver) }).toArray(function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.post("/user/acceptFriendRequest", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let friendReq = req.body._id;
	let receiver = req.body.receiver;
	let sender = req.body.sender;
		
	dbo.collection("friends").updateOne({'user': ObjectId(receiver)}, {$push: {'friends': {'friend': ObjectId(sender)}}}, function(err, result) 
	{
		if (err) throw err;
		dbo.collection("friends").updateOne({'user': ObjectId(sender)}, {$push: {'friends': {'friend': ObjectId(receiver)}}}, function(err, result) 
		{
			if (err) throw err;
			dbo.collection("friend_requests").deleteOne({'_id': ObjectId(friendReq)}, function(err, obj) 
			{
				if (err) throw err;
				res.end();
			});
		});
	});
});

app.get("/user/getUserFriends", function(req,res)
{
	var dbo = _database.db("geeks");
	
	let user = req.query.user;
	//console.log(user);
	dbo.collection('friends').aggregate([
	{ '$match': { 'user':  ObjectId(user) } },
    { $lookup:
       {
         from: 'user',
         localField: 'friends.friend',
         foreignField: '_id',
         as: 'friendsList'
       }
     }
    ]).toArray(function(err, result) {
		res.json(result);
  });
});

app.delete("/user/deleteFriend", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let toDelete = req.query.friend;
	let user = req.query.user;
	dbo.collection("friends").updateOne({'user': ObjectId(user)}, { $pull: { friends: { friend: ObjectId(toDelete) } } }, function(err, result)
	{
		dbo.collection("friends").updateOne({'user': ObjectId(toDelete)}, { $pull: { friends: { friend: ObjectId(user) } } }, function(err, result)
		{
			res.end();
		});
	});
});

const profile_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'avatars/')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

const upload_avatar = multer({ storage: profile_storage })
app.post("/user/uploadAvatar", upload_avatar.array('file', 1), function(req, res)
{
	//console.log(req.files);
	res.end();
});

app.get("/merch/list", function(req, res)
{
	var dbo = _database.db("geeks");
	//console.log(req.query);
	let user = ObjectId(req.query.user);
	
	var query = { user: user };
	dbo.collection("user_merch").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.post("/merch/add", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let user = req.body.user;
	req.body.user = ObjectId(user);
	
	dbo.collection("user_merch").insertOne(req.body, function(err, result) 
	{
		if (err) throw err;
		res.json(req.body._id);
	});
});

const usermerch_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'user_merch/')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

const upload_usermerch = multer({ storage: usermerch_storage })
app.post("/merch/uploadImage", upload_usermerch.array('file', 1), function(req, res)
{
	//console.log(req.files);
	res.end();
});

app.put("/merch/update", function(req, res)
{
	let merch = req.body._id;
	let user = req.body.user;
	
	req.body._id = ObjectId(merch);
	req.body.user = ObjectId(user);
	
	var dbo = _database.db("geeks");
	dbo.collection("user_merch").updateOne({'_id': ObjectId(merch)}, { $set: req.body }, function(err, result2) 
	{
		if (err) throw err;
		res.end();
	});
});

app.delete("/merch/delete", function(req, res)
{
	let merch = req.query.id;
	
	var dbo = _database.db("geeks");
	dbo.collection("user_merch").deleteOne({'_id': ObjectId(merch)}, function(err, obj) 
	{
		if (err) throw err;
		res.end();
	});
});

app.post("/cart/getMerchs", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let data = JSON.parse(req.body.list);
	console.log(data);
	let arr = [];
	var result = Object.entries(data);
	
	for (var i = 0; i < result.length; i++) 
	{ 
		arr.push(ObjectId(result[i][0]));
    }
	
	dbo.collection('user_merch').find({"_id" : {"$in" : arr}}).toArray(function(err, result)
	{
		if (err) throw err;
		res.json(result);
	});
});

app.post("/cart/buyMerch", function(req, res)
{
	let pkey = req.body.privatekey;
	var key = '6IAVE+56U5t7USZhb+9wCcqrTyJHqAu09j0t6fBngNo=';
	var bytes  = CryptoJS.AES.decrypt(pkey, key);
	var originalText = bytes.toString(CryptoJS.enc.Utf8);
	console.log(originalText);
	
	delete req.body.privatekey;
	
	var q = queue();
	
	var dbo = _database.db("geeks");
	
	let userId = req.body.user;
	req.body.user = ObjectId(userId);
	let arr = {};
	for (const [key, value] of Object.entries(req.body.orderList))
	{
		arr[ObjectId(key)] = value;
	}
	
	req.body.orderList = arr;
	
	hasWallet(userId, function(result1)
	{
		if (result1.length > 0)
		{
			let info = web3.eth.accounts.privateKeyToAccount('0x'+originalText);
			console.log(info);
			if (info.address != result1[0]["adr"])
			{
				res.json("Wrong private key");
			}
			else
			{
				contract.methods.balanceOf(result1[0]["adr"]).call((error, balance) => 
				{
					var promises = [];
					let numericalBalance = Number(balance.toString());
					
					for (const [key, value] of Object.entries(arr))
					{
						promises.push
						(
							new Promise((resolve, reject) => {
								getMerchFromId(ObjectId(key), function(res2)
								{
									if (res2 != null)
									{
										resolve(res2);
									}
									else
									{
										//reject("No");
									}
								})
							})
						);
					};
					Promise.all(promises).then((results) => {
						var priceToPay = 0;
						results.forEach(result =>
						{
							let unitPrice = result["price"];
							let wantedQte = arr[result["_id"]];
							let finalPrice = unitPrice * wantedQte;
							priceToPay += finalPrice;
						});
						if (priceToPay > numericalBalance)
						{
							res.json("Not enough balance");
						}
						else
						{
							dbo.collection("orders").insertOne(req.body, function(err, result4) {
								if (err) throw err;
							});
							results.forEach(result =>
									{
								
										let wantedQte = result["quantity"] - arr[result["_id"]];
										result["quantity"] = wantedQte;
										let idToUpdate = ObjectId(result["_id"]);
										dbo.collection("user_merch").updateOne({'_id': ObjectId(result["_id"])}, { $set: result }, function(err, result3) 
										{
											if (err) throw err;
										});
										
										hasWallet(result["user"], function(sellerResult)
										{
											if (sellerResult.length > 0)
											{
												console.log("sending "+arr[result["_id"]] * result["price"] + " to " + sellerResult[0]["adr"]);
												//transferTokens(adrFrom, adrTo, privateKey, amount)
												transferTokens(result1[0]["adr"], sellerResult[0]["adr"], originalText, arr[result["_id"]] * result["price"]);
											}
										});
									});
						}
					});
				});
			}
		}
		else
		{
			res.json("No wallet");
		}
	});
});
//web3.eth.sendSignedTransaction('0x' + transaction.serialize().toString('hex')).on('receipt', console.log);

app.get("/orders/history", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let user = req.query.user;
	
	dbo.collection('orders').find({"user" : ObjectId(user)}).toArray(function(err, result)
	{
		if (err) throw err;
		res.json(result);
	});
});

app.get('/steam', function(req, res){
	res.end();
});

app.get('/steam/account', ensureAuthenticated, function(req, res){
	res.end();
});

app.get('/steam/logout', function(req, res){
  req.logout();
  res.redirect('/');
});
  
app.get('/auth/steam', (req, res, next) => {
  req.session.user = req.query.user;
  console.log(req.session);
  req.session.save(next);
}, passport.authenticate('steam'));

app.get('/auth/steam/return',
  passport.authenticate('steam', { failureRedirect: '/steam' }),
  function(req, res) 
  {
	var dbo = _database.db("geeks");
	let user = ObjectId(req.session.user);
	let steamId = req.user["_json"]["steamid"];
	dbo.collection("steam").insertOne({'user': user, 'steamId': steamId}, function(err, result) {
		if (err) throw err;
		res.redirect('http://localhost:4200');
	});
});

app.get("/user/steamKey", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.query.user;
	
	dbo.collection("steam").findOne({'user': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
		if (result != null)
		{
			steam.getUserSummary(result["steamId"]).then(summary => {
				res.json(summary);
			});
		}
		else
		{
			res.json("");
		}
	});
});

app.get("/game/gameDetails", function(req, res)
{
	let game = req.query.game;
	steam.getGamePlayers("321040").then(summary => {
		res.json(summary);
	});
});

app.delete("/user/unlinkSteam", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = ObjectId(req.query.user);
	var mykey = {'user': user};
	dbo.collection("steam").deleteOne(mykey, function(err, obj) 
	{
		if (err) throw err;
		res.end();
	});
});

app.get("/user/getPlayerGames", function(req, res)
{
	let steamId = req.query.steamId;
	steam.getUserOwnedGames(steamId).then(summary => {
		res.json(summary);
	});
});

app.get("/user/searchByUsername", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let username = req.query.username;
	
	dbo.collection("user").find({'username': new RegExp(username, 'i')}).toArray(function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});



var clients = {};


io.on('connection', function(socket){
  socket.on("sendMessage", function(message){
    console.log("Message received:");
    console.log(message);
	getUserFromId(message.fromId, function(result)
	{
		let participant =  {
			id: message.fromId,
			displayName: result["username"],
			status: 0,
			avatar: "http://localhost:1337/avatars/"+message.fromId+".jpg"
		}
		console.log(participant["avatar"]);
		io.emit("messageReceived", {
		  user: participant,
		  message: message
		});

		console.log("Message dispatched.");
	});
  });
  
  socket.on('new-message', (message) => {
  console.log(message);
  
    io.emit('new-message',{
              msg:message.msg,
              user:message.name,
              date:new Date()
          })
    
  });
});

app.post("/user/listFriends",function(req, res)
{
	var dbo = _database.db("geeks");
	
	let user = req.body.user;
	dbo.collection('friends').aggregate([
	{ '$match': { 'user':  ObjectId(user) } },
    { $lookup:
       {
         from: 'user',
         localField: 'friends.friend',
         foreignField: '_id',
         as: 'friendsList'
       }
     }
    ]).toArray(function(err, result) 
	{
		var usersCollection = [];
		if (result[0] != undefined)
		{
			result[0]["friendsList"].forEach(element => {
			usersCollection.push({
				participant: {
					id: element._id,
					displayName: element.username,
					status: 1,
					avatar: "http://localhost:1337/avatars/"+element._id+".jpg"
					}
				});
			});
		}
		console.log(usersCollection);
		res.json(usersCollection);
	});
});
app.get("/forum/categories", function(req, res)
{
    var dbo = _database.db("geeks");
	
	dbo.collection('ForumCategories').aggregate([
    { $lookup:
       {
         from: 'SubReddits',
         localField: '_id',
         foreignField: 'idCategory',
         as: 'reddiDetails'
       }
     }
    ]).toArray(function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.post("/thread/add", function(req, res)
{
  console.log(req.body);
   var dbo = _database.db("geeks");
    let title = req.body.title;
    let description = req.body.description;
    let sender = req.body.sender.id;
	let adddate = req.body.addtime;
    dbo.collection("threads").insertOne(req.body, function(err, res2)
                {
                    if (err) throw err;
					res.json(req.body._id);
                   console.log(req.body._id);
                   
                });
});




app.get("/thread/find", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("threads").findOne({'_id': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});
app.get("/topic/find", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let user = req.query.id;
	dbo.collection("SubReddits").findOne({'_id': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
		
		res.json(result);
	});
	
});


app.get("/post/find", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let user = req.query.id;
	dbo.collection("forumpost").findOne({'_id': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
		
		res.json(result);
	});
	
});



app.get("/thread/get", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("threads").find({"subreddit._id":user}).toArray(function(err, result) 
{
	res.json(result);
});
});

app.get("/thread/getit", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("threads").findOne({'_id': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
	
		res.json(result);
	});
});

const attachements_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'thread_attachements/')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

const upload_attachement = multer({ storage: attachements_storage })
app.post("/thread/uploadattachement", upload_attachement.array('file', 1), function(req, res)
{	
	console.log("aze");
	console.log(req.body);
	res.end();
});
app.post("/reply/add", function(req, res)
{
  console.log(req.body);
   var dbo = _database.db("geeks");
    let content = req.body.content;
	let thread = req.body.threadid;
    let sender = req.body.sender.id;
	let replytime = req.body.replytime;
    dbo.collection("forumpost").insertOne(req.body, function(err, res2)
                {
                    if (err) throw err;
					res.json(req.body._id);
                   
                   
                });
});
app.get("/replys/get", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("forumpost").find({"threadid":user}).toArray(function(err, result) 
{
	res.json(result);
});
});

app.get("/post/like", function(req, res)
{
var dbo = _database.db("geeks");
	let post_id = req.query.id;	
	let likes = req.query.likes;
console.log(req.query);
	dbo.collection("forumpost").updateOne({'_id': ObjectId(post_id)}, { $set: {likes: likes} }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});


app.get("/thread/like", function(req, res)
{
var dbo = _database.db("geeks");
	let thread_id = req.query.id;
		

	let	likes = req.query.likes ;
	
	dbo.collection("threads").updateOne({'_id': ObjectId(thread_id)}, { $set: {likes: likes} }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.post("/thread/react", function(req, res)
{
  
   var dbo = _database.db("geeks");
   
	let thread = req.body.threadid;
    let sender = req.body.senderid;
	console.log(req.body);
    dbo.collection("threadreacts").insertOne(req.body, function(err, res2)
                {
                    if (err) throw err;
					res.json(req.body._id);
                   
                   
                });
});
app.post("/post/react", function(req, res)
{
  console.log(req.body);
   var dbo = _database.db("geeks");
  let thread = req.body.postid;
    let sender = req.body.senderid;
    dbo.collection("postracts").insertOne(req.body, function(err, res2)
                {
                    if (err) throw err;
					res.json(req.body._id);
                   
                   
                });
});

app.get("/threadreacts/get", function(req, res)
{
 var dbo = _database.db("geeks");
 let user = req.query.id;
 let threadid = req.query.threadid
	var query = {$or:[{"Thread":threadid}, {"user":user}]};
	
	dbo.collection("threadreacts").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		cb(result);
	});
});


app.get("/topicreacts/get", function(req, res)
{
 var dbo = _database.db("geeks");
 let user = req.query.id;
 let topicid = req.query.topicid
	var query = {$or:[{"Thread":topicid}, {"user":user}]};
	
	dbo.collection("threadreacts").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		cb(result);
	});
});




app.get("/threadreacts/get", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("threadreacts").find({"Thread":user}).toArray(function(err, result) 
{
	res.json(result);
});
});


app.get("/coupon/update", function(req, res)
{
	console.log("gi");
	console.log(req.body);
var dbo = _database.db("geeks");
	let post_id = req.query.id;	
	let statuss = req.query.status;
console.log(req.query);
	dbo.collection("coupons").updateOne({'_id': ObjectId(post_id)}, { $set: {status: statuss} }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});



app.post("/coupons/add", function(req, res)
{
 
   var dbo = _database.db("geeks");
    let user = req.body.couponplayer;
    let addtime = req.body.validatetime;
    let userpubkey = req.body.userpubkey;
	let coupon = req.body.coupongames;
	let montant = req.body.montant;
	let pontentielgain = req.body.potentielgain;
	let etat = req.body.stauts;
    let payementstatus =req.body.payementstatus
   
    dbo.collection("coupons").insertOne(req.body, function(err, res2)
                {
                    if (err) throw err;
					res.json(req.body._id);
                   
                   
                });
});

app.get("/coupons/find", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("coupons").find({"couponplayer":user}).toArray(function(err, result) 
{
	res.json(result);
});
});

app.get("/coupon/find", function(req, res)
{
	var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("coupons").findOne({'_id': ObjectId(user)}, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.get("/thread/checker", function(req, res)
{
	var dbo = _database.db("geeks");
	
	let user = req.query.id;
	let threadid = req.query.thread;
	getlikebythreadanduser(user,threadid,function(result){
		
		res.json(result.length);
		
	})
	
});

//FUNCTION
function getlikebythreadanduser(user, thread, cb)
{
	var dbo = _database.db("geeks");
	
	var query = {$or:[{"user":user}, {"Thread":thread}]};
	
	dbo.collection("threadreacts").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		cb(result);
	});
}



app.get("/post/checker", function(req, res)
{
	var dbo = _database.db("geeks");
	console.log(req.query);
	let user = req.query.id;
	let post = req.query.postid;
	getlikebypostanduser(user,post,function(result){
		console.log(result);
		res.json(result.length);
		
	})
	
});

//FUNCTION
function getlikebypostanduser(user, post, cb)
{
	var dbo = _database.db("geeks");
	
	var query = {$or:[{"user":user}, {"post":post}]};
	
	dbo.collection("postracts").find(query).toArray(function(err, result) 
	{
		if (err) throw err;
		cb(result);
	});
}





app.get("/summoners/get", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("riotaccounts").find({}).toArray(function(err, result) 
{
	res.json(result);
});
});



app.post("/bet/transaction", (req, res) => {
	console.log(req.body);
    let firstpublickey = req.body.firstpublickey;
    let firstprivatekey = req.body.firstprivatekey;
    let secondpublickey = req.body.secondpublickey;
    let amount = req.body.amount;

    web3.eth.getTransactionCount(firstpublickey)
      .then((count) =>
      {
        let rawTransaction= {
            'from': firstpublickey,
            'gasPrice': web3.utils.toHex(20 * 1e9),
            'gasLimit': web3.utils.toHex(210000),
            'to':tokenAddress,
            'value': 0x0,
            'data': contract.methods.transfer(secondpublickey, amount).encodeABI(),
            'nonce': web3.utils.toHex(count) 

        };    

        let transaction =  new Tx(rawTransaction, {'chain' : 'rinkeby'});
        const privateKey = Buffer.from(
            firstprivatekey,
            'hex',
          )
        transaction.sign(privateKey);
        web3.eth.sendSignedTransaction('0x' + transaction.serialize().toString('hex'))
            .on('transactionHash',console.log);
            res.end();

      })



})
var upload = multer({ dest: 'thread_attachements/' })

app.post('/uploadthreads', upload.single("picture"), function (req,res) {
    console.log("Received file" + req);

    var src = fs.createReadStream(req.file.path);
    var dest = fs.createWriteStream('thread_attachements/' + req.file.originalname);
    src.pipe(dest);
    src.on('end', function() {
    	fs.unlinkSync(req.file.path);
    	res.json('OK: received ' + req.file.originalname);
    });
    src.on('error', function(err) { res.json('Something went wrong!'); });
  
  })

app.get("/tournament/test/:hello", (req, res) => {
    let hello = req.params.hello;
    res.json(hello)
    console.log(hello);
})


app.get("/tournament/createtournament/:iduser/:gamename/:type/:tournamentname/:startdate/:starttime/:gameregion/:gamemap/:gameformat/:entry/:entryfee/:tournamentfee/:lastPrice/:minteams/:maxteams/:createtype/:accessCode/:reason", (req, res) => {
 
    let iduser = req.params.iduser;
    let gamename = req.params.gamename;
    let type = req.params.type;
    let tournamentname = req.params.tournamentname;
    let startdate = req.params.startdate;
    let starttime = req.params.starttime;
    let gameregion = req.params.gameregion;
    let gamemap = req.params.gamemap;
    let gameformat = req.params.gameformat;
    let entry = req.params.entry;
    let entryfee = req.params.entryfee;
    let tournamentfee = req.params.tournamentfee;
    let minteams = req.params.minteams;
    let maxteams = req.params.maxteams;
    let createtype = req.params.createtype;
    let accessCode = req.params.accessCode;
    let reason = req.params.reason;
    let lastPrice = req.params.lastPrice;


  console.log("Samer");
  
  
    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var myobj = {iduser:iduser,gamename: gamename,type: type, tournamentname : tournamentname,startdate:startdate,starttime:starttime,gameregion:gameregion,gamemap:gamemap,gameformat:gameformat,entry:entry,entryfee:entryfee,tournamentfee:tournamentfee,lastPrice:lastPrice,minteams:minteams,maxteams:maxteams,createtype:createtype,etatTournoi : '1',accessCode:accessCode,reason:reason,bracket:0,archive:1};
        dbo.collection("tournament").insertOne(myobj, function(err, res) {
          if (err) throw err;
          console.log("1 document inserted");
          db.close();
        });
      });
      });








      app.get("/tournament/createbracketfortorunament/:tournamentid/:phase/:player1/:player2", (req, res) => {
        let tournamentid = ObjectId(req.params.tournamentid);
        let phase = req.params.phase;
        let player1 = req.params.player1;
        let player2 = req.params.player2;

        MongoClient.connect(url, function(err, db) {
            if (err) throw err;
            var dbo = db.db("geeks");
            var myobj = {tournamentid:tournamentid,phase:phase,player1:player1,player2:player2,state:0};
            dbo.collection("brackettournament").insertOne(myobj, function(err, res) {
              if (err) throw err;
              console.log("1 document inserted for bracket !");
              db.close();
             
            });
            res.end();
          });
          });

















      app.get("/tournament/numberofplacestournament/:tournamentname", (req, res) => {

        let tournamentname = req.params.tournamentname
        var number = 0;
    
        MongoClient.connect(url, function(err, db) {
          if (err) throw err;
          var dbo = db.db("geeks");
          var query = { tournamentname: tournamentname};
          dbo.collection("tournament").find(query).toArray(function(err, result) {
            if (err) throw err;
            console.log(result);
            db.close();
            res.json(result.length)

            res.end();
          });

        });
        console.log("Number called ");

      })


      app.get("/tournament/numberofplacesroomtournament/:tournamentname", (req, res) => {

        let tournamentname = req.params.tournamentname
        var number = 0;
    
        MongoClient.connect(url, function(err, db) {
          if (err) throw err;
          var dbo = db.db("geeks");
          var query = { tournamentname: tournamentname};
          dbo.collection("roomtournament").find(query).toArray(function(err, result) {
            if (err) throw err;
            console.log(result);
            db.close();
            res.json(result.length)
            res.end();
          });

        }); 
      })


      app.get("/tournament/checkjoined/:tournamentname/:iduser", (req, res) => {

        let tournamentname = req.params.tournamentname
        let iduser = ObjectId(req.params.iduser)
        
    
        MongoClient.connect(url, function(err, db) {
          if (err) throw err;
          var dbo = db.db("geeks");
          var query = { tournamentname: tournamentname,iduser:iduser};
          dbo.collection("roomtournament").find(query).toArray(function(err, result) {
            if (err) throw err;
            db.close();
            console.log("checkoined : " + result.length);
            res.json(result.length)
            res.end();
          });

        });
      })



    



  




  app.get("/tournament/jointournament/:iduser/:tournamentname", (req, res) => {
 
    let iduser = ObjectId(req.params.iduser);
    let tournamentname = req.params.tournamentname;

  

    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var myobj = {iduser:iduser,tournamentname:tournamentname};
        dbo.collection("roomtournament").insertOne(myobj, function(err, res) {
          if (err) throw err;
          console.log("1 ROOM  inserted");
          db.close();
        });
      });
  })



  app.get("/tournament/newtournament/:iduser", (req, res) => {

    let iduser =   ObjectId(req.params.iduser);

  MongoClient.connect(url, function(err, db) {
    if (err) throw err;
    var dbo = db.db("geeks");
    var query = {iduser: iduser};
    dbo.collection('roomtournament').aggregate([
      { $match: { iduser: iduser } },
      { $lookup:
         {
           from: 'tournament',
           localField: 'tournamentname',
           foreignField: 'tournamentname',
           as: 'newtournament'
         }
       }
      ]).toArray(function(err, result) {
      if (err) throw err;
      console.log("GOOD");
      res.json(result);
      db.close();
    });
  });

});





app.get("/tournament/getplayersforbracket/:tournamentname", (req, res) => {

  let tournamentname = req.params.tournamentname;

MongoClient.connect(url, function(err, db) {
  if (err) throw err;
  var dbo = db.db("geeks");
  var query = {tournamentname: tournamentname};
  dbo.collection('roomtournament').aggregate([
    { $match: { tournamentname: tournamentname } },
    { $lookup:
       {
         from: 'user',
         localField: 'iduser',
         foreignField: '_id',
         as: 'players'
       }
     }
    ]).toArray(function(err, result) {
    if (err) throw err;
    console.log("WE GOT PLAYERS");
    res.json(result);
    db.close();
  });
});

});





  app.get("/tournament/gettournamentbycode/:accessCode", (req, res) => {

    let accessCode = req.params.accessCode

    MongoClient.connect(url, function(err, db) {
      if (err) throw err;
      var dbo = db.db("geeks");
      var query = { accessCode: accessCode};
      dbo.collection("tournament").find(query).toArray(function(err, result) {
        if (err) throw err;
        console.log(result);
        db.close();
        res.json(result);
        res.end();
      });
    });
  })


  app.get("/tournament/getBracketPlayers/:tournamentid", (req, res) => {

    let tournamentid = ObjectId(req.params.tournamentid)

    MongoClient.connect(url, function(err, db) {
      if (err) throw err;
      var dbo = db.db("geeks");
      var query = { tournamentid: tournamentid};
      dbo.collection("brackettournament").find(query).toArray(function(err, result) {
        if (err) throw err;
        console.log("BRACKET CALLED");
        db.close();
        res.json(result);
        res.end();
      });
    });
  })






  
app.get("/tournament/alltournaments", (req, res) => {

    

    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var mysort = { startdate: 1 };
        dbo.collection("tournament").find({}).sort(mysort).toArray(function(err, result) {
          if (err) throw err;
          console.log(result);
          db.close();
          res.json(result);
          res.end();
        });
      });

  })

  






  app.get("/tournament/mytournaments/:iduser", (req, res) => {

    let iduser = req.params.iduser;
    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var query = { iduser: iduser};
        dbo.collection("tournament").find(query).toArray(function(err, result) {
          if (err) throw err;
          console.log(result);
          db.close();
          res.json(result);
          res.end();
        });
      });

  })


  app.get("/tournament/mytournamentsaccepted/:iduser", (req, res) => {

    let iduser = req.params.iduser;
    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var query = { iduser: iduser,etatTournoi:'2'};
        dbo.collection("tournament").find(query).toArray(function(err, result) {
          if (err) throw err;
          console.log(result);
          db.close();
          res.json(result);
          res.end();
        });
      });

  })


  app.get("/tournament/alltournamentswait", (req, res) => {


    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var query = {etatTournoi:'1'};
        dbo.collection("tournament").find(query).toArray(function(err, result) {
          if (err) throw err;
          console.log(result);
          db.close();
          res.json(result);
          res.end();
        });
      });

  })



  app.get("/tournament/alltournamentacc", (req, res) => {


    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var query = {etatTournoi:'2'};
        dbo.collection("tournament").find(query).toArray(function(err, result) {
          if (err) throw err;
          console.log(result);
          db.close();
          res.json(result);
          res.end();
        });
      });

  })

  app.get("/tournament/acceptrequesttournament/:idtournoi", (req, res) => {

    
    let idtournoi = req.params.idtournoi;

    MongoClient.connect(url, function(err, db) {
      if (err) throw err;
      var dbo = db.db("geeks");
      var accessCode = generator.generateCodes(pattern, howMany, options);
      var myquery = { _id: ObjectId(idtournoi) };
      var newvalues = { $set: {etatTournoi: "2",accessCode:accessCode[0]} };
      dbo.collection("tournament").updateOne(myquery, newvalues, function(err, res) {
        if (err) throw err;
        console.log("1 document updated");
        db.close();
      });
    });
    res.end();

  })




  app.get("/tournament/declinerequesttournament/:idtournoi/:reason", (req, res) => {

    
    let idtournoi = req.params.idtournoi;
    let reason = req.params.reason;

    MongoClient.connect(url, function(err, db) {
      if (err) throw err;
      var dbo = db.db("geeks");
      var myquery = { _id: ObjectId(idtournoi) };
      var newvalues = { $set: {etatTournoi: "0",reason: reason} };
      dbo.collection("tournament").updateOne(myquery, newvalues, function(err, res) {
        if (err) throw err;
        console.log("1 document updated");
        db.close();
      });
    });
    res.end();

  })



  app.get("/tournament/testcode", (req, res) => {


    // Generate an array of random unique codes according to the provided pattern:
    var codes = generator.generateCodes(pattern, howMany, options);

    res.json(codes);

  })











  app.get("/tournament/checkplayerbalance/:publickey", (req, res) => {
      let publickey = req.params.publickey;
    contract.methods.balanceOf(publickey).call((error, balance) => 
			{
				console.log(balance.toString() + " ESD");
				res.json({"balance": balance.toString()});
			});


  })




  

  app.get("/tournament/transaction/:firstpublickey/:firstprivatekey/:secondpublickey/:amount", (req, res) => {
    let firstpublickey = req.params.firstpublickey;
    let firstprivatekey = req.params.firstprivatekey;
    let secondpublickey = req.params.secondpublickey;
    let amount = req.params.amount;

    web3.eth.getTransactionCount(firstpublickey)
      .then((count) =>
      {
        let rawTransaction= {
            'from': firstpublickey,
            'gasPrice': web3.utils.toHex(20 * 1e9),
            'gasLimit': web3.utils.toHex(210000),
            'to':tokenAddress,
            'value': 0x0,
            'data': contract.methods.transfer(secondpublickey, amount).encodeABI(),
            'nonce': web3.utils.toHex(count) 

        };    

        let transaction =  new Tx(rawTransaction, {'chain' : 'rinkeby'});
        const privateKey = Buffer.from(
            firstprivatekey,
            'hex',
          )
        transaction.sign(privateKey);
        web3.eth.sendSignedTransaction('0x' + transaction.serialize().toString('hex'))
            .on('transactionHash',console.log);
            res.end();

      })


})

const PATH = './uploads';

let storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, PATH);
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now()+file.originalname)
  }
});

let upload_chat = multer({
  storage: storage
});

app.get('/api', function (req, res) {
  res.end('File catcher');
});


app.post('/api/upload', upload_chat.single('image'), function (req, res) {
  if (!req.file) {
    console.log("No file is available!");
    return res.send({
      success: false
    });

  } else {
    console.log('File is available!');
    return res.send({
      success: true
    })
  }
});

app.get("/follow/list/", (req, res) => {

      //  let firas = req.params.firas
     
        MongoClient.connect(url, function(err, db) {
          if (err) throw err;
          var dbo = db.db("geeks");
         // var query = { iduser: firas};
          dbo.collection("suivie").find({}).toArray(function(err, result) {
            if (err) throw err;
            console.log(result);
            db.close();
            res.json(result)
            res.end();
          });

        });
      })
      //////////////////////////////////////////////chaaaaaaaaaaatttttttttt//////////////////


	  
	  
	  
	  //////////////////////////////////////////////////ajout folow//////////////////////////////////////////////
	app.post("/profil/follow/", (req, res) => {
    let iduser = req.body.receiver;
    let idfollower = req.body.sender;
	 let idfollow = req.body.idfollow;
   
  
  
  
    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var myobj = {iduser:iduser,idfollower: idfollower,idfollow:idfollow};
        dbo.collection("suivie").insertOne(myobj, function(err, result) {
          if (err) throw err;
          console.log("1 document inserted");
          db.close();
           res.json(result)
		  console.log(iduser + ' ' + idfollower);
            res.end();
        });
      });
      });
	  
	  	  //////////////////////////////////////////////////afficher list abonnement//////////////////////////////////////////////

	   app.get("/abonnement/offert/:iduser", (req, res) => {

        let iduser = req.params.iduser
     
        MongoClient.connect(url, function(err, db) {
          if (err) throw err;
          var dbo = db.db("geeks");
          var query = { iduser: iduser};
          dbo.collection("abonnement").find(query).toArray(function(err, result) {
            if (err) throw err;
            console.log(result);
            db.close();
            res.json(result)
            res.end();
          });

        });
      })
	  
	  
	  	  //////////////////////////////////////////////////ajout abonnement//////////////////////////////////////////////

app.post("/profil/abonnement/", (req, res) => {
    let iduser = req.body.iduser;
    let idstreamer = req.body.idstreamer;
	let dateex = req.body.dateex;
	let level = req.body.level;

   
  
  
  
    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db("geeks");
        var myobj = {iduser:iduser,idstreamer: idstreamer,dateex:dateex,level:level};
        dbo.collection("abonnement").insertOne(myobj, function(err, result) {
          if (err) throw err;
          console.log("1 abonnement inserted");
          db.close();
           res.json(result)
		  console.log(iduser + ' ' + idstreamer);
            res.end();
        });
      });
      });


app.post("/replyreport/add", function(req, res)
{
  console.log(req.body);
   var dbo = _database.db("geeks");
    let title = req.body.title;
    let description = req.body.description;
    let sender = req.body.sender;
	let reply = req.body.reply;
	let adddate = req.body.addtime;
	let state = req.body.state;
    dbo.collection("replyreports").insertOne(req.body, function(err, res2)
                {
                    if (err) throw err;
					res.json(req.body._id);
                   console.log(req.body._id);
                   
                });
});

app.post("/replycoupon/add", function(req, res)
{
  console.log(req.body);
   var dbo = _database.db("geeks");
    let title = req.body.title;
    let description = req.body.description;
    let sender = req.body.sender;
	let coupon = req.body.coupon;
	let adddate = req.body.addtime;
	let state = req.body.state;
    dbo.collection("couponsreports").insertOne(req.body, function(err, res2)
                {
                    if (err) throw err;
					res.json(req.body._id);
                   console.log(req.body._id);
                   
                });
});

app.get("/ReplyReports/get", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("replyreports").find({}).toArray(function(err, result) 
{
	res.json(result);
});
});
app.get("/BetReports/get", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("couponsreports").find({}).toArray(function(err, result) 
{
	res.json(result);
});
});




app.delete("/post/remove", function(req, res) {
	 var dbo = _database.db("geeks");
	 let user = req.query.id;
	 console.log(req.query);
  var dbo = _database.db("geeks");
	dbo.collection("forumpost").deleteOne({'_id': ObjectId(user)}, function(err, obj) 
	{
		if (err) throw err;
		res.end();
	});
})

app.get("/report/stateupdate", function(req, res)
{
var dbo = _database.db("geeks");
	let post_id = req.query.id;	
	let st = req.query.stt;
console.log(req.query);
	dbo.collection("replyreports").updateOne({'_id': ObjectId(post_id)}, { $set: {state: st} }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.get("/reportbet/stateupdate", function(req, res)
{
var dbo = _database.db("geeks");
console.log(req.query.stt);
	let post_id = req.query.id;	
	let st = req.query.stt;
console.log(req.query);
	dbo.collection("couponsreports").updateOne({'_id': ObjectId(post_id)}, { $set: {state: st} }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});


app.get("/report/stateupdate", function(req, res)
{
var dbo = _database.db("geeks");
	let post_id = req.query.id;	
	let st = req.query.stt;
console.log(req.query);
	dbo.collection("replyreports").updateOne({'_id': ObjectId(post_id)}, { $set: {state: st} }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.get("/bannedusers/get", function(req, res)
{
    var dbo = _database.db("geeks");
	let user = req.query.id;
	dbo.collection("user").find({"forumstate":user}).toArray(function(err, result) 
{
	res.json(result);
});
});

app.get("/user/banforum", function(req, res)
{
var dbo = _database.db("geeks");
	let user = req.query.id;	
	let st = req.query.stt;
	
console.log(req.query);
	dbo.collection("user").updateOne({'_id': ObjectId(user)}, { $set: {forumstate: st} }, function(err, result) 
	{
		if (err) throw err;
		res.json(result);
	});
});

app.post("/contact/mail",function (req, res) {
	console.log(req);
	let sender = req.body.sendermail;	
	let content = req.body.content;
	let subject = req.body.subject;
	let passwd = req.body.passworddd;
  
  var mailOptions = {
		from: req.body.sendermail,
		to: 'geeksoverflow@gmail.com',
		subject: req.body.subject,
		html: '<p>'+req.body.content+'</p>'// plain text body
	};
	
	var transporterz = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: req.body.sendermail,
    pass: req.body.passworddd
  }
});
	transporterz.sendMail(mailOptions, function(error, info)
	{
		if (error) 
		{
		console.log(error);
		} 
		else 
		{
			console.log('Email sent: ' + info.response);
		}
	});
  
  }); 

server.listen(1337);