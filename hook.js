module.exports = Hook;

function Hook () {}

Hook.prototype.sendMessage = function (msg) {
	let fetch = require('node-fetch');
	fetch('https://yourURL.here/webhook/'+msg);
}
