module.exports = Hook;
const fetch = require('node-fetch');

function Hook () {}
Hook.prototype.sendMessage = function (msg) {
	// POST SUBJECT-LINE TO 255
	let body = { message: msg };
	fetch('http://localhost:3000', { // 255 POST
		method: 'post',
		body:    JSON.stringify(body),
		headers: { 'Content-Type': 'application/json' }
	})
	.catch(err => {console.error(err); return;})
	.then(res => res.text())
	.then(text => {}); //console.log('255-REPLY: '+text)
}
