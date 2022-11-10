let fs = require('fs');
let ssh2 = require('ssh2');
let crypto = require('crypto');

let extracted = Date.now();
let usernames = JSON.parse(fs.readFileSync(__dirname + "/db.json").toString());

async function autoSaving() {
	let a = JSON.stringify(usernames, null, "\t");
	while (true) {
		if (a != fs.readFileSync(__dirname + "/db.json").toString()) {
			fs.writeFileSync(__dirname + "/db.json", JSON.stringify(usernames, null, "\t"));
		}
		a = JSON.stringify(usernames, null, "\t");
		await setTimeoutAsync(1000);
	}
}
autoSaving();

function authenticate(a, b) {
	if (usernames.hasOwnProperty(a))
		if (usernames[a].password == sha256(b)) return true;
	return false;
}

function authenticateKey(a, ctx) {
	if (usernames.hasOwnProperty(a)) {
		if (usernames[a].publicKey) {
			if (ctx.key.algo == ssh2.utils.parseKey(usernames[a].publicKey).type) return ((ctx.key.data.toString() == ssh2.utils.parseKey(usernames[a].publicKey).getPublicSSH().toString()) && ssh2.utils.parseKey(usernames[a].publicKey).verify(ctx.blob, ctx.signature));
		}
	}
	return false;
}

function newInputChar(buf) {
	return new Promise(async function (resolve) {
		let a = setInterval(function () {
			let b = buf.read();
			if (b != null) {
				b = b.toString();
				clearInterval(a);
				resolve(b);
			}
		});
	});
}

function sha256(str) {
	if (str == "") return str;
	return require("crypto").createHash('sha256').update(str).digest('base64');
}

function setTimeoutAsync(ms) {
	return new Promise(function (a) {
		setTimeout(function () {
			a();
		}, ms);
	});
}

function sendMsg(u, m) {
	chatEmitter.emit("message", {
		message: m,
		username: u
	});
}

process.on("warning", function (w) {
	//Sorry I don't hear you!
	console.warn(w);
});

process.on("unhandledException", function (e) {
	//Sorry I don't hear you!
	console.error(e);
});

process.on("unhandledRejection", function (e) {
	//Sorry I don't hear you!
	console.error(e);
});


function newInputs(buf, noPrint = false) {
	let input = "";
	return new Promise(async function (resolve) {
		while (!input.endsWith("\r")) {
			let newChar = await newInputChar(buf);
			if (newChar.charCodeAt() != 27)
				if (newChar.charCodeAt() != 127) input = input + newChar;
			if (!noPrint)
				if (newChar.charCodeAt() != 27)
					if (newChar.charCodeAt() != 127) buf.write(newChar);
			if (newChar.charCodeAt() == 127 && input.length != 0) {
				buf.write("\b");
				buf.write(" ");
				buf.write("\b");
				input = input.split("");
				input.length = input.length - 1;
				input = input.join("");
			}
		}
		buf.write("\n");
		input = input.split("");
		input.length = input.length - 1;
		input = input.join("");
		resolve(input);
	});
}

let chatEmitter = {
	on: function (ev, fn) {
		if (!this._map.hasOwnProperty(ev)) this._map[ev] = [];
		this._map[ev].push(fn);
	},
	emit: function (ev, data) {
		if (!this._map.hasOwnProperty(ev)) this._map[ev] = [];
		for (let fn of this._map[ev]) {
			try {
				fn(data);
			} catch {

			}
		}
	},
	_map: {

	}
}

function checkUsernameAvailability(abc, buf) {
	if (!usernames.hasOwnProperty(abc.authedAs)) {
		buf.close();
		return buf.destroy();
	}
	if (usernames[abc.authedAs].banned) {
		buf.write("Your account is currently locked/banned. You cannot use this System without a correct account.\r\n");
		buf.close();
		return buf.destroy();
	}
}

function checkIfUserAdmin(abc, buf) {
	if (!usernames.hasOwnProperty(abc.authedAs)) {
		buf.close();
		return buf.destroy();
	}
	if (!usernames[abc.authedAs].admin) {
		buf.write("Permission denied. Socket destroyed.\r\n");
		buf.close();
		return buf.destroy();
	}
}

new ssh2.Server({
	hostKeys: [fs.readFileSync('./hostkeys')]
}, client => {
	client
		.on('authentication', ctx => {
			if (ctx.method == "password") {
				if (authenticate(ctx.username, ctx.password)) {
					client.authedAs = ctx.username;
					return ctx.accept();
				}
			} else if (ctx.method == "publickey") {
				if (authenticateKey(ctx.username, ctx)) {
					client.authedAs = ctx.username;
					return ctx.accept();
				}
			}
			ctx.reject();
		})
		.on('ready', () => {
			client
				.on('session', (accept) => {
					let session = accept();
					let stream;
					session.on('shell', async function (accept) {
						stream = accept();
						checkUsernameAvailability(client, stream);
						stream.write("Welcome to PCsoft SSH server, " + client.authedAs + "!\r\n");
						stream.write("\r\n");
						stream.write(" * Documentation and support: PC#7105 Discord\r\n");
						stream.write("\r\n");
						stream.write("No updates available\r\n");
						stream.write("up " + ((new Date(Date.now() - extracted)).getFullYear() - new Date(0).getFullYear()).toString() + " years " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getMonth().toString() + " months " + ((new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getDate() - 1).toString() + " days " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getHours().toString() + " hours " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getMinutes().toString() + " minutes " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getSeconds().toString() + " seconds\r\n");
						if (!usernames[client.authedAs].admin) stream.write("$ ");
						if (usernames[client.authedAs].admin) stream.write("# ");
						while (true) {
							let input = await newInputs(stream);
							let cmd = input.split(" ")[0];
							let args = input.split(" ").slice(1);
							checkUsernameAvailability(client, stream);
							if (cmd == "help") {
								stream.write("help - Outputs the list of commands and their functions (what do they do)\r\nexit - Disconnect from SSH server.\r\npasswd - Change password\r\nnewuser - Allows a guest or an admin to create an account for joining the network.\r\ndeluser - Allows an admin to remove an account. A non-admin running this command will get removed.\r\nbanuser - Allows an admin to ban someone's account. The commands won't be accepted from that account.\r\nrouser - Allows an admin to make account read-only. The commands related to writing to database won't be accepted from that account. The user guest is not read-writeable.\r\nadmuser - Allows an admin to make an user admin. The users guest and root can't have their state changed.\r\nchat - Open chat app. Only available for R/W users.\r\nautoregister - Auto-registrate yourself with UltimateLogon.\r\nwhoami - Prints out what is your username\r\nuserlist - Provides the userlist (currently the list is only available to read/write users due to security reasons)\r\nuptime - View how long the server has been running for.\r\nkeyauth || pubkey (pubkey acts the same as keyauth) - Set up public key auth. (a better alternative to password)\r\nman [command] - view manual for command\r\n");
							} else if (cmd == "exit") {
								stream.close();
								stream.destroy();
							} else if (cmd == "passwd") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									stream.write("Old password: ");
									let oldP = await newInputs(stream, true);
									checkUsernameAvailability(client, stream);
									if (sha256(oldP) == usernames[client.authedAs].password) {
										stream.write("\rNew password: ");
										checkUsernameAvailability(client, stream);
										usernames[client.authedAs].password = sha256(await newInputs(stream, true));
										stream.write("\rYou'll need to re-enter the system for the changes to take effect.\r\n");
										stream.close();
										stream.destroy();
									} else {
										stream.write("\rInvalid old password. No changes were made.\r\n");
									}
								} else {
									stream.write("Your account is write-protected. No changes were made.\r\n");
								}
							} else if (cmd == "newuser") {
								checkUsernameAvailability(client, stream);
								if (usernames[client.authedAs].readonly || usernames[client.authedAs].admin) {
									stream.write("Enter new username: ");
									let username = await newInputs(stream);
									if (usernames.hasOwnProperty(username)) {
										stream.write("Username was taken. Think of another username and re-execute this command. No changes were made.\r\n")
									} else {
										stream.write("Enter your password (keep it secret!): ");
										let password = sha256(await newInputs(stream, true));
										usernames[username] = {
											password: password,
											admin: false,
											readonly: false,
											banned: false
										};
										stream.write("\rYou may now log in with your new username.\r\n");
									}
								} else {
									stream.write("Your account is okay. No changes were made.\r\n");
								}
							} else if (cmd == "autoregister") {
								checkUsernameAvailability(client, stream);
								if (usernames[client.authedAs].readonly || usernames[client.authedAs].admin) {
									stream.write("UltimateLogon autoregistration\r\n");
									stream.write("On the page https://ultimatelogon.pcprojects.tk/deviceLogon,\r\n");
									stream.write("Type in the code: ");
									try {
										let a = await fetch("https://ultimatelogon.pcprojects.tk/deviceStartSess");
										a = await a.json();
										stream.write(a.code + "\r\n");
										while (true) {
											try {
												let b = await fetch("https://ultimatelogon.pcprojects.tk/deviceDetails?device=" + a.token);
												b = await b.json();
												if (b.user) {
													stream.write("Registering...\r\n");
													if (usernames.hasOwnProperty(b.user.username)) {
														stream.write("Username was taken. Think of another username and execute newuser command. No changes were made.\r\n")
													} else {
														usernames[b.user.username] = {
															password: b.user.password,
															admin: false,
															readonly: false,
															banned: false
														};
														stream.write("\rYou may now log in with your new username.\r\n");
													}
													break;
												}
												await setTimeoutAsync(10000);
											} catch {
												stream.write("Something went wrong. Try again!\r\n");
												break;
											}
										}
									} catch {
										stream.write("00000000\r\n");
										stream.write("Something went wrong. Try again!\r\n")
									}
								} else {
									stream.write("Your account is okay. No changes were made.\r\n");
								}
							} else if (cmd == "deluser") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									checkUsernameAvailability(client, stream);
									if (usernames[client.authedAs].admin) {
										stream.write("Enter username: ");
										let username = await newInputs(stream);
										checkIfUserAdmin(client, stream);
										if (username != "root" & username != "guest") {
											delete usernames[username];
											stream.write("User removed successfully.\r\n");
										} else {
											stream.write("Invalid parameters.\r\n");
										}
									} else {
										checkUsernameAvailability(client, stream);
										delete usernames[client.authedAs];
										stream.write("User removed successfully.\r\n");
										stream.close();
										return stream.destroy();
									}
								} else {
									stream.write("Your account is write-protected. No changes were made.\r\n");
								}
							} else if (cmd == "banuser") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									checkUsernameAvailability(client, stream);
									if (usernames[client.authedAs].admin) {
										stream.write("Enter username: ");
										let username = await newInputs(stream);
										checkIfUserAdmin(client, stream);
										if (username != "guest" && username != "root") {
											usernames[username].banned = !usernames[username].banned;
											stream.write("User state changed successfully (banned = " + usernames[username].banned.toString() + ").\r\n");
										} else {
											stream.write("Invalid parameters.\r\n");
										}
									} else {
										stream.write("banuser: Permission denied\r\n");
									}
								} else {
									stream.write("banuser: Permission denied\r\n");
								}
							} else if (cmd == "rouser") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									checkUsernameAvailability(client, stream);
									if (usernames[client.authedAs].admin) {
										stream.write("Enter username: ");
										let username = await newInputs(stream);
										checkIfUserAdmin(client, stream);
										if (username != "guest" && username != "root") {
											usernames[username].readonly = !usernames[username].readonly;
											stream.write("User state changed successfully (readonly = " + usernames[username].readonly.toString() + ").\r\n");
										} else {
											stream.write("Invalid parameters.\r\n");
										}
									} else {
										stream.write("rouser: Permission denied\r\n");
									}
								} else {
									stream.write("rouser: Permission denied\r\n");
								}
							} else if (cmd == "admuser") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									checkUsernameAvailability(client, stream);
									if (usernames[client.authedAs].admin) {
										stream.write("Enter username: ");
										let username = await newInputs(stream);
										checkIfUserAdmin(client, stream);
										if (username != "guest" && username != "root") {
											usernames[username].admin = !usernames[username].admin;
											stream.write("User state changed successfully (admin = " + usernames[username].admin.toString() + ").\r\n");
										} else {
											stream.write("Invalid parameters.\r\n");
										}
									} else {
										stream.write("admuser: Permission denied\r\n");
									}
								} else {
									stream.write("admuser: Permission denied\r\n");
								}
							} else if (cmd == "chat") {
								let bas = false;
								if (!usernames[client.authedAs].readonly) {
									checkUsernameAvailability(client, stream);
									chatEmitter.emit("message", {
										message: client.authedAs + " has connected",
										username: "root"
									});
									if (client.authedAs == "root") {
										stream.write("chatd: you should not connect as root!\r\n");
									}
									let prevMsg = "";
									chatEmitter.on("message", function (data) {
										if (bas) return;
										checkUsernameAvailability(client, stream);
										if (prevMsg) {
											stream.write("\r" + " ".repeat(prevMsg.length > 79 ? 79 : 79 - prevMsg.length) + "\r");
										}
										stream.write("<" + data.username + ">: " + data.message + "\r\n");
										prevMsg = "<" + data.username + ">: " + data.message;
										stream.write("Type your message: ");
									});
									stream.write("Type your message: ");
									while (true) {
										if (bas) return;
										checkUsernameAvailability(client, stream);
										let newMsg = await newInputs(stream);
										if (newMsg != "!quitChat") {
											stream.write("\r" + " ".repeat(newMsg.length > 79 ? 79 : 79 - newMsg.length) + "\r");
											chatEmitter.emit("message", {
												message: newMsg,
												username: client.authedAs
											});
										} else {
											bas = true;
											chatEmitter.emit("message", {
												message: client.authedAs + " has disconnected",
												username: "root"
											});
											break;
										}
										session.on("end", function() {
											if (bas) return;
											chatEmitter.emit("message", {
												message: client.authedAs + " has disconnected with an error",
												username: "root"
											});
										});
										session.on("end", function() {
											if (bas) return;
											chatEmitter.emit("message", {
												message: client.authedAs + " has disconnected with an error",
												username: "root"
											});
										});
									}
								} else {
									stream.write("Your account is write-protected.\r\n");
								}
							} else if (cmd == "whoami") {
								checkUsernameAvailability(client, stream);
								stream.write(client.authedAs + "\r\n");
							} else if (cmd == "userlist") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									stream.write(Object.keys(usernames).join("\r\n") + "\r\n");
								} else {
									stream.write("Your account is write-protected.\r\n");
								}
							} else if (cmd == "uptime") {
								stream.write("up " + ((new Date(Date.now() - extracted)).getFullYear() - new Date(0).getFullYear()).toString() + " years " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getMonth().toString() + " months " + ((new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getDate() - 1).toString() + " days " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getHours().toString() + " hours " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getMinutes().toString() + " minutes " + (new Date(Date.now() - extracted + (new Date().getTimezoneOffset() * 1000 * 60))).getSeconds().toString() + " seconds\r\n");
							} else if (cmd == "evaljs") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									if (usernames[client.authedAs].admin) {
										if (client.authedAs == "root") {
											stream.write("servicing: " + JSON.stringify(eval(args.join(" ")), null, "\t").replaceAll("\r\n", "\n").replaceAll("\n", "\r\n") + "\r\n");
										} else {
											stream.write(cmd + ": command not found\r\n");
										}
									} else {
										stream.write(cmd + ": command not found\r\n");
									}
								} else {
									stream.write(cmd + ": command not found\r\n");
								}
							} else if (cmd == "pubkey" || cmd == "keyauth") {
								checkUsernameAvailability(client, stream);
								if (!usernames[client.authedAs].readonly) {
									stream.write("Okay, everything seems fine now. Paste in your SSH public key: ");
									let pubkey = await newInputs(stream);
									let letThrough = false;
									try {
										ssh2.utils.parseKey(pubkey);
										letThrough = true;
									} catch {
										checkUsernameAvailability(client, stream);
										delete usernames[client.authedAs].publicKey;
										stream.write("Public key authentication cannot be set for this account. Try again later.\r\n");
									}
									if (letThrough) {
										checkUsernameAvailability(client, stream);
										usernames[client.authedAs].publicKey = pubkey;
										stream.write("Public key authentication is set successfully.\r\n");
									}
								} else {
									stream.write("Your account is write-protected. No changes were made.\r\n");
								}
							} else if (cmd == "man") {
								stream.write("THE COMMAND MANUAL\r\n");
								if (args[0] == "suspc") {
									stream.write("SUSPC INFORMATION\r\n");
									stream.write("\r\n");
									stream.write("\tHello, seems like PC sent you to this page cuz you said that he is sus.\r\n");
									stream.write("\r\n");
									stream.write("YOU'RE NOT WRONG:\r\n");
									stream.write("\tYou're not wrong that PC is sus. He is. But try to actually stop saying\r\n");
									stream.write("\tthat PC is sus, spamming is not great.\r\n");
									stream.write("\r\n");
									stream.write("WHY TO STOP:\r\n");
									stream.write("\tPC understands that he is sus. But sometimes he needs some help or just\r\n");
									stream.write("\tsomeone to talk to. PC is tired of being spammed with SUS PC and other\r\n");
									stream.write("\tmessages. Try for once to stop saying that PC is sus. See, he programmed\r\n");
									stream.write("\tthis, and said the phrase \"PC is sus\" too much, you should have already\r\n");
									stream.write("\tunderstood that PC understands that he SUS.\r\n");
									stream.write("\r\n");
									stream.write("HOW DOES THAT AFFECT ME:\r\n");
									stream.write("\tYou said PC is sus.\r\n");
									stream.write("\r\n");
									stream.write("HOW TO MAKE PC NO LONGER SEND YOU TO THIS PAGE:\r\n");
									stream.write("\tStop saying that PC is sus if PC is present on a messaging service. (such as ssh-pub chat)\r\n");
								} else if (args[0] == "evaljs") {
									stream.write("EVALJS INFORMATION\r\n");
									stream.write("\r\n");
									stream.write("\tThere's no such command. Stop. You won't get access.\r\n");
								} else if (args[0] == "pubkey" || args[0] == "keyauth") {
									stream.write("KEYAUTH || PUBKEY COMMAND\r\n");
									stream.write("\r\n");
									stream.write("DESCRIPTION:\r\n");
									stream.write("\tpubkey or keyauth allows you to set a public key. This is experimental and may\r\n");
									stream.write("not work properly.\r\n");
									stream.write("\r\n");
									stream.write("USAGE:\r\n");
									stream.write("\t1. Input pubkey command. (it takes no arguments)\r\n");
									stream.write("\t2. Enter in your public key.\r\n");
									stream.write("\t3. Try to log out (exit command) and log back in! # this step is optional\r\n");
								} else {
									stream.write("No such command found in Manual Pages Database.\r\n");
								}
							} else {
								stream.write(cmd + ": command not found\r\n");
							}
							if (!usernames[client.authedAs].admin) stream.write("$ ");
							if (usernames[client.authedAs].admin) stream.write("# ");
						}
					});
					session.on("pty", function (accept) {
						accept();
					});
					session.on("sftp", function (nul, reject) {
						reject();
						nul = undefined;
					});
					session.on("exec", function (accept) {
						let chan = accept();
						chan.stderr.write("We do not support execution on the server. Use shells instead.\r\n")
						chan.exit("SIGINT", false, "We do not support execution on the server. Use shells instead.");
						chan.close();
						chan.destroy();
					})
				})
		}).on("error", function (e) {
			//Sorry I don't hear you!
			console.error(e);
		});;
}).listen(3022, '0.0.0.0', function () {
	console.log('Listening on port ' + this.address().port);
});