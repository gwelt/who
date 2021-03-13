var nmap = require('node-nmap');
var express = require('express');
var app = express();
var server = require('http').createServer(app);

const scan_object='192.168.1.0/24';
const interval_seconds=300;
const max_latest_scans_times=60;
const max_idle_hours=72;
const port=3000;

scan();
let interval=setInterval(function(){scan()},interval_seconds*1000);
var clients = [];
var latest_scans_times = [];

server.listen(port, function () { console.log('\x1b[44m SERVER LISTENING ON PORT '+port+' \x1b[0m'); });
app.use('(/who)?/api', function(req,res) {
	res.set('Content-Type','application/json');
	let resObj={"latest_scans_times":latest_scans_times,"clients":clients};
	res.end(JSON.stringify(resObj));
});
app.use('(/who)?/:ip/:force_refresh?', function(req,res) {
	res.set('Content-Type','application/json');
	let c = getClient(req.params.ip,undefined,true);
	if (c) {c.scan(res,(req.params.force_refresh=='force'))} else {res.sendStatus(404)}
});
app.use('(/who)?/', function(req,res) {
	res.set('Content-Type','text/html');
	res.end(create_output());
});

function Client(name,ip) {
	this.name = name;
	this.ip = ip;
	this.occurences = [];
	this.last_seen = undefined;
	this.portscan = undefined;
}

Client.prototype.scan = function(res,force) {
	if (this.portscan==undefined||force) {
		console.log('SCANNING: '+this.ip);
		let client=this;
		var osandports = new nmap.OsAndPortScan(this.ip);
		osandports.on('complete',function(data){
			console.log(data);
			client.portscan=(data.length)?data:undefined;
			res.end(JSON.stringify(data));
		});
		osandports.on('error', function(error){
			console.log('ERROR: '+error);
			client.portscan=undefined;
			res.end(JSON.stringify(error));
		});
		osandports.startScan();
	} else {
		res.end(JSON.stringify(this.portscan));
	}
};

function scan() {
	let quickscan = new nmap.QuickScan(scan_object);
	quickscan.on('complete', function(data){
	 	console.log(new Date()+' | '+data.length+' clients | '+quickscan.scanTime+' ms');
	 	process_scan_results(data);
	});
	quickscan.on('error', function(error){
		console.log(error);
	});
	quickscan.startScan();
}

function process_scan_results(data) {
	let time = new Date();
	latest_scans_times.push(time);
	while (latest_scans_times.length>max_latest_scans_times) {latest_scans_times.splice(0,1)};
	while (data.length>0) {
		let scan_client = data.pop();
		let client = getClient(scan_client.ip,scan_client.hostname);
		client.occurences.push(time);
		client.last_seen=time;
	}
	housekeeping(time);
}

function getClient(ip,name,nocreate) {
	var client = clients.find((e)=>{return (e.ip==ip) && ((e.name==name)||(name==undefined))});
	if (client==undefined && !nocreate) {
		client = new Client(name,ip);
		clients.push(client);
	}
	return client;
}

function housekeeping(time) {
	clients = clients.filter((e)=>{return time-e.last_seen<max_idle_hours*60*60*1000});
	clients.forEach((c)=>{
		c.occurences = c.occurences.filter((e)=>{return e>=latest_scans_times[0]});
	});
	clients.sort((a, b) => {
		const num1 = Number(a.ip.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
		const num2 = Number(b.ip.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
		return num1-num2;
	});
}

function create_output() {
	let res='<pre><code>nmap | '+interval_seconds+' seconds interval | '+max_latest_scans_times+' scans history\n';
	let ip_maxlength = Math.max(...clients.map(c=>c.ip?c.ip.length:0));
	let name_maxlength = Math.max(...clients.map(c=>c.name?c.name.length:0));
	res+=''.padEnd(ip_maxlength+name_maxlength+max_latest_scans_times+6,'=')+'\n';
	res+=clients.reduce((a,c)=>{
		let title=c.portscan?JSON.stringify(c.portscan).replace(/\"/g,""):'click to scan '+c.ip;
		let r='<a style=text-decoration:none href=/'+c.ip+' title="'+title+'">'+(c.ip||'').padEnd(ip_maxlength,' ')+'</a>   '+(c.name||'').padEnd(name_maxlength+3,' ');
		if (c.occurences.length<1) {
			r+='last seen: '+c.last_seen;
		} else {
			r+=latest_scans_times.reduce((a2,c2)=>{
				if (c.occurences.find((o)=>{return o==c2})) {return '\u2588'+a2} else {return '\u2591'+a2}
			},'');
		}
		return a+r+'\n';
	},'');
	res+='</code></pre>';
	return res;
}
