var nmap = require('node-nmap');
var express = require('express');
var app = express();
var server = require('http').createServer(app);
var fs = require('fs');

var config = {}; try {config=require('./config.json')} catch(err){};
var port = process.env.PORT || config.port || 3000;
const Hook = require('./hook.js');
let hook = new Hook();

/*let network_interfaces=require('os').networkInterfaces();
let interfaces = Object.keys(network_interfaces);//['wlan0'][0]['address'];
//interfaces.
console.log(network_interfaces);
process.exit(0);
*/

function List_of_Clients(scan_object,interval_seconds,max_latest_scans_times,max_idle_hours,datafile) {
	this.clients = [];
	this.latest_scans_times = [];
	
	this.scan_object=scan_object||'192.168.1.0/24';
	this.interval_seconds=interval_seconds||300;
	this.max_latest_scans_times=max_latest_scans_times||36;
	this.max_idle_hours=max_idle_hours||72;
	this.datafile = datafile||'data/clientlist.json';

	this.import((m)=>{
		console.log(m);
		this.scan();
		let clientlist=this;
		let interval=setInterval(function(){clientlist.scan()},clientlist.interval_seconds*1000);
	});
}

List_of_Clients.prototype.import = function(callback) {
  fs.readFile(this.datafile, 'utf8', (err, data)=>{
    if (err){callback('NO DATAFILE. NO IMPORT.')} else {
      try {
      	let d = JSON.parse(data);
      	d.clients.forEach((c)=>{
      		let nc=this.getClient(c.ip,c.name,true);
      		nc.occurences=c.occurences.map(o=>new Date(o));
      		nc.last_seen=new Date(c.last_seen);
      		nc.portscan=c.portscan;
       	})
      	this.latest_scans_times = d.latest_scans_times.map(i=>new Date(i));
      } catch (err) {console.log('Import aborted. '+err)}
      callback(this.clients.length+' CLIENTS LOADED. LAST UPDATE: '+this.latest_scans_times[this.latest_scans_times.length-1].toISOString());
    }
  });
}

List_of_Clients.prototype.export = function(callback) {
  fs.writeFile(this.datafile, JSON.stringify(this), 'utf8', (err)=>{
    callback(err?err:'File '+this.datafile+' saved.');
  });
}

List_of_Clients.prototype.getClient = function (ip,name,create_if_not_found) {
	name=name?name.replace(/\.fritz\.box/g,''):undefined;
	var client = this.clients.find((e)=>{return (e.ip==ip) && ((e.name==name)||(name==undefined))});
	if (create_if_not_found && client==undefined) {
		client = new Client(ip,name);
		this.clients.push(client);
	}
	return client;
}

List_of_Clients.prototype.scan = function () {
	let clientlist=this;
	let quickscan = new nmap.QuickScan(this.scan_object);
	quickscan.on('complete', function(data){
		let time = new Date();
	 	console.log(time.toISOString()+' | '+data.length+' clients | '+quickscan.scanTime+' ms');
		clientlist.latest_scans_times.push(time);
		while (clientlist.latest_scans_times.length>clientlist.max_latest_scans_times) {clientlist.latest_scans_times.splice(0,1)};
		while (data.length>0) {
			let scan_client = data.pop();
			let client = clientlist.getClient(scan_client.ip,scan_client.hostname,true);
			client.occurences.push(time);
			client.last_seen=time;
			if (client.occurences.length==1) {
				// do something if a new network-client appears
				if (clientlist.latest_scans_times.length>clientlist.max_latest_scans_times/2) {
					hook.sendMessage('NETWORK+ '+client.name);					
				}
			};
		}
		clientlist.housekeeping(time);
	});
	quickscan.on('error', function(error){
		console.log(error);
	});
	quickscan.startScan();
}

List_of_Clients.prototype.housekeeping = function (time) {
	this.clients = this.clients.filter((e)=>{return time.getTime()-e.last_seen.getTime()<this.max_idle_hours*60*60*1000});
	this.clients.forEach((c)=>{
		c.occurences = c.occurences.filter((e)=>{return e.getTime()>=this.latest_scans_times[0].getTime()});
	});
	this.clients.sort((a, b) => {
		const num1 = Number(a.ip.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
		const num2 = Number(b.ip.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
		return num1-num2;
	});
}

List_of_Clients.prototype.create_output = function (requestingIP) {
	let res='<html><head><link rel="preconnect" href="https://fonts.gstatic.com"><link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet"><style type=text/css>code {font-family: "Share Tech Mono", monospace;} div {margin:3% 5%} body {font-size:1.4rem; background:#021d02; color:#00ff00cc;} a {color:#00ff00cc;text-decoration:none;} ::selection {background:#fff;}</style></head><body><div><pre><code>nmap | '+this.scan_object+' | '+this.interval_seconds+' seconds interval | '+this.max_latest_scans_times+' scans history\n';
	let ip_maxlength = Math.max(...this.clients.map(c=>c.ip?c.ip.length:0));
	let name_maxlength = Math.max(...this.clients.map(c=>c.name?c.name.length:0));
	res+=''.padEnd(ip_maxlength+name_maxlength+this.max_latest_scans_times+6,'\u2505')+'\n';
	
	this.clients.sort((a,b)=>{
		if (b.occurences.length==a.occurences.length) {
			if (b.occurences.length==0 && b.last_seen.getTime()!==a.last_seen.getTime()) {
				return b.last_seen.getTime()-a.last_seen.getTime();
			} else {
				const num1 = Number(a.ip.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
				const num2 = Number(b.ip.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
				return num1-num2;				
			}
		} else {return b.occurences.length-a.occurences.length};
	});
	
	res+=this.clients.reduce((a,c)=>{
		let title=c.portscan?JSON.stringify(c.portscan).replace(/\"/g,""):'click to scan '+c.ip;
		let r='<a href=/'+c.ip+' title="'+title+'">'+(c.ip||'').padEnd(ip_maxlength,' ')+'</a>   '+(c.name||'').padEnd(name_maxlength+3,' ');
		if (c.occurences.length<1) {
			r+='last seen: '+c.last_seen.toLocaleString();
		} else {
			r+=this.latest_scans_times.reduce((a2,c2)=>{
				if (c.occurences.find((o)=>{return o.getTime()==c2.getTime()})) {return '\u2588'+a2} else {return '\u2591'+a2}
			},'');
		}
		return a+r+'\n';
	},'');
	res+='</code></pre></div></body></html>';
	return res;
}

function Client(ip,name,occurences,last_seen,portscan) {
	this.ip = ip;
	this.name = name;
	this.occurences = occurences||[];
	this.last_seen = last_seen;
	this.portscan = portscan;
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

var clientlist = new List_of_Clients(config.scan_object,config.interval_seconds,config.max_latest_scans_times,config.max_idle_hours,config.datafile);

process.on('SIGINT', function(){ console.log('SIGINT'); clientlist.export((m)=>{console.log(m);process.exit(0)},true)});
process.on('SIGTERM', function(){ console.log('SIGTERM'); clientlist.export((m)=>{console.log(m);process.exit(0)},true)});

server.listen(port, function () { console.log('\x1b[44m SERVER LISTENING ON PORT '+port+' \x1b[0m'); });
app.use('(/who)?/api', function(req,res) {
	res.set('Content-Type','application/json');
	res.end(JSON.stringify(clientlist));
});
app.use('(/who)?/:ip/:force_refresh?', function(req,res) {
	res.set('Content-Type','application/json');
	let c = clientlist.getClient(req.params.ip);
	if (c) {c.scan(res,(req.params.force_refresh=='force'))} else {res.sendStatus(404)}
});
app.use('(/who)?/', function(req,res) {
	res.set('Content-Type','text/html');
	res.end(clientlist.create_output(req.connection.remoteAddress));
});
