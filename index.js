var fs = require('fs');
var HEPjs = require('hep-js');
var dgram = require('dgram');
const Tail = require('tail').Tail;
var socket = dgram.createSocket("udp4");
//const axios = require("axios");
const { Resolver } = require('dns');
const resolver = new Resolver();
resolver.setServers(['8.8.8.8']);

var getSocket = function (type) {
  if (undefined === socket) {
    socket = dgram.createSocket(type);
    socket.on('error', socketErrorHandler);
    var socketCloseHandler = function () {
      if (socketUsers > 0) {
        socket = undefined;
        --socketUsers;
        getSocket(type);
      }
    };
    socket.on('close', socketCloseHandler);
  }
  return socket;
}

var hep_server = 'a.dd.re.ss';
var hep_port = 'hep_port';
var hep_pass = '';
var hep_id = hep_id;

var socket;

socket = dgram.createSocket("udp4");
socket = getSocket('udp4');

var debug = true; 
var stats = {rcvd: 0, parsed: 0, hepsent: 0, err: 0, heperr: 0 }; 

var sendHEP3 = function(msg,rcinfo){
  if (rcinfo && msg) {
    var msg = msg + '\r\n';
    try {
      if (debug) console.log('Sending HEP3 Packet to '+ hep_server + ':' + hep_port + '...');
      if (! typeof msg === 'string' || ! msg instanceof String) msg = JSON.stringify(msg);
      var hep_message = HEPjs.encapsulate(msg.toString(),rcinfo);
      stats.parsed++;
      if (hep_message && hep_message.length) {
        socket.send(hep_message, 0, hep_message.length, hep_port, hep_server, function(err) {
          stats.hepsent++;
        });
      } else { console.log('HEP Parsing error!'); stats.heperr++; }
    } 
    catch (e) {
      console.log('HEP3 Error sending!');
      console.log(e);
      stats.heperr++;
    }
  }
}

var tail = new Tail("/root/SBC.log");

tail.watch()
tail.on('line', data => {
  if (data.match(/[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \(#[0-9]+\)Route found \([0-9]+\), Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9_-]+\:?[0-9]+? \-\> [a-zA-Z0-9-_]+\:?[0-9]+?\) \#012\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[A-Za-z:0-9-@.]+\]$/gm)) {
    //Cannot send undefined message to heplify-server. Simply logging warning.
    //console.log('Log with undefined SIP Flow');
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \(#\d+\)Route found \(\d+\), Route by Address, IP Group \d+ \-\> \d+ \([a-zA-Z0-9-_]+:?[0-9]? \-\> [a-zA-Z0-9_-]+:?[0-9]?\)\, Url\:\w+\:\d+\; \#012\(N [0-9]+\) \-\-\-\- Incoming SIP Message from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d+) to SIPInterface #\d+ \([a-zA-Z0-9_-]+:?[0-9]+?\) ([A-Z]+) TO\(#\d+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d+ from [a-zA-Z]+ \#\d+ \([a-zA-Z0-9_-]+:[0-9]+?\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[\w]+\:[0-9-@:.]+\]$/gm)) {
    //parsing srcIp, SrcPort and protocol variables
    var initialinmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \(#\d+\)Route found \(\d+\), Route by Address, IP Group \d+ \-\> \d+ \([a-zA-Z0-9-_]+:?[0-9]? \-\> [a-zA-Z0-9_-]+:?[0-9]?\)\, Url\:\w+\:\d+\; \#012\(N [0-9]+\) \-\-\-\- Incoming SIP Message from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+) to SIPInterface #\d+ \([a-zA-Z0-9_-]+:?[0-9]+?\) ([A-Z]+) TO\(#\d+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d+ from [a-zA-Z]+ \#\d+ \([a-zA-Z0-9_-]+:[0-9]+?\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[\w]+\:[0-9-@:.]+\]$/gm.exec(data);;
    // parsing dstIp and dstPort from SIP URI
    // if in URI have IP
    var srcIp = initialinmsglog[1];
    var srcPort = initialinmsglog[2];
    var protocol = initialinmsglog[3];
    var msg = initialinmsglog[4];
    if (initialinmsglog[4].match(/[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(initialinmsglog[4]);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      //var hrTime = process.hrtime();
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else 
    //if in URI have domain name
    if (initialinmsglog[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z-_]+\.[a-zA-Z-_]+)\:?([0-9]+)? /gm)) {
      var rawdstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z-_]+\.[a-zA-Z-_]+)\:?([0-9]+)? /gm.exec(initialinmsglog[4]);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          var dstIp = addresses[0];
          var protocol = initialinmsglog[3];
          if (rawdstipport[2] !== undefined ) {
            var dstPort = rawdstipport[2];
          } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          sendHEP3(msg,rcinfo);
          // stop send packet to heplify-server
        });
      })();
    }// else console.log();
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9_-]+\:?[0-9]+?\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-:@.]+\]$/gm)) {
    //parsing dstIp, dstPort and protocol
    var outresponcemsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9_-]+\:?[0-9]+?\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-:@.]+\]$/gm.exec(data);
    var dstIp = outresponcemsglog[1];
    var dstPort = outresponcemsglog[2];
    var protocol = outresponcemsglog[3];
    var msg = outresponcemsglog[4];
    if (outresponcemsglog[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outresponcemsglog[4]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (outresponcemsglog[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outresponcemsglog[4]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    }// else console.log();

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9_-]+\:?[0-9]+?\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    //setting incoming line to variable
    var inmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9_-]+\:?[0-9]+?\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inmsglog[1];
    var srcPort = inmsglog[2];
    var protocol = inmsglog[3];
    var msg = inmsglog[4];
    if (inmsglog[4].match(/[\w]+ sip\:[a-zA-Z0-9+]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9+]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(inmsglog[4]);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      var datenow = new Date().getTime();
      var time_sec = Math.floor(datenow / 1000);
      var time_usec = datenow - (time_sec*1000);
      var msg = msg.replace(/#012/gm, '\r\n')
      //var msg = msg + '\r\n';
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else 
    //if in URI have domain name
    if (inmsglog[4].match(/[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsglog[4]);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    } else if (inmsglog[4].match(/[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsglog[4]);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
      // getting dstIp and Port from Via Header
    } else if (inmsglog[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm)) {
      var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm.exec(inmsglog[4]);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsglog[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm)) {
      var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm.exec(inmsglog[4]);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } //else console.log(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9_-]+\:?[0-9]+? \-\> [a-zA-Z0-9-_]+\:?[0-9]+?\) \#012\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) [\w]+ TO\(#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9.:@-]+\]$/gm)) {
    var initialinmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=.*\] +\(N [0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9_-]+\:?[0-9]+? \-\> [a-zA-Z0-9-_]+\:?[0-9]+?\) \#012\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) [\w]+ TO\(#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9.:@-]+\]$/gm.exec(data);
    var srcIp = initialinmsglog[1];
    var srcPort = initialinmsglog[2];
    var protocol = initialinmsglog[3];
    var msg = initialinmsglog[4];
    if (msg.match(/[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (msg.match(/[\w]+ sip\:[a-zA-Z0-9+]+\@([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9+]+\@([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else
    //if in URI have domain name
    if (msg.match(/[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(msg);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
      //if in URI have domain name with username
    } else if (msg.match(/[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(msg);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    }// else console.log(msg);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N [0-9]+\) \(\#[0-9]+\)Route found \([0-]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+? \-\> [a-zA-Z0-9-_]+\:?[0-9]+?\)\, Url\:[a-zA-Z]+\:[0-9]+\; \#012\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9:@.-]+\]$/gm)) {
    var initialinmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N [0-9]+\) \(\#[0-9]+\)Route found \([0-]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+? \-\> [a-zA-Z0-9-_]+\:?[0-9]+?\)\, Url\:[a-zA-Z]+\:[0-9]+\; \#012\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N [0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9:@.-]+\]$/gm.exec(data);
    //setting incoming line to variable
    var srcIp = initialinmsglog[1];
    var srcPort = initialinmsglog[2];
    var protocol = initialinmsglog[3];
    var msg = initialinmsglog[4];
    if (msg.match(/[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (msg.match(/[\w]+ sip\:[a-zA-Z0-9+]+\@([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9+]+\@([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else
    //if in URI have domain name
    if (msg.match(/[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(msg);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
      //if in URI have domain name with username
    } else if (msg.match(/[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(msg);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    }// else console.log(msg);
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 #012 \[[a-zA-Z0-9:.@-]+\]$/gm)) {
    //setting incoming line to variable
    var inmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N [0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_]+\:?[0-9]+?\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 #012 \[[a-zA-Z0-9:.@-]+\]$/gm.exec(data);
    var srcIp = inmsglog[1];
    var srcPort = inmsglog[2];
    var protocol = inmsglog[3];
    var msg = inmsglog[4];
    if (msg.match(/[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (msg.match(/[\w]+ sip\:[a-zA-Z0-9+]+\@([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9+]+\@([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else
    //if in URI have domain name
    if (msg.match(/[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(msg);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
      //if in URI have domain name with username
    } else if (msg.match(/[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var rawdstipport = /[\w]+ sip\:[a-zA-Z0-9-_+]+\@([a-zA-Z0-9-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(msg);
      (async () => {
        dstIp = await resolver.resolve4(rawdstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (rawdstipport[2] !== undefined ) {
              var dstPort = rawdstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    } else if (msg.match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm)) {
      var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (msg.match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm)) {
      var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?([0-9]+)?\;/gm.exec(msg);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } //else console.log(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]/gm)) {
    var inmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]/gm.exec(data);
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    if (inmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else {
      var dstipport = /\#012Via\: [\w]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/g.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      if (inmsgipport[4].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm)) {
        var dstipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm.exec(inmsgipport[4]);
        var dstIp = dstipport[1];
        if (dstipport[2] !== undefined ) {
          var dstPort = dstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      } else if (inmsgipport[4].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm)) {
        var dstipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm.exec(inmsgipport[4]);
        (async () => {
          dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
            //console.log('addresses: ', addresses[0]);
            if(addresses !== undefined) {
              var dstIp = addresses[0];
              if (dstipport[2] !== undefined ) {
                var dstPort = dstipport[2];
              } else var dstPort = '5060';
              //console.log('srcIp: ', srcIp);
              //console.log('srcPort: ', srcPort);
              //console.log('dstIp: ', dstIp);
              //console.log('dstPort: ', dstPort);
              // start send packet to heplify-server
              if (msg) {
                var datenow = new Date().getTime();
                var time_sec = Math.floor(datenow / 1000);
                var time_usec = datenow - (time_sec*1000);
                var msg = msg.replace(/#012/gm, '\r\n')
                //var msg = msg + '\r\n';
                var rcinfo = { 
                  type: 'HEP',
                  version: 3,
                  payload_type: 'SIP',
                  captureId: hep_id,
                  capturePass: '',
                  ip_family: 2,
                  time_sec: time_sec,
                  time_usec: time_usec,
                  protocol: 6,
                  proto_type: 1,
                  srcIp: srcIp,
                  dstIp: dstIp,
                  srcPort: srcPort,
                  dstPort: srcPort 
                }
                sendHEP3(msg,rcinfo);
              }
              // stop send packet to heplify-server
            }
          });
        })()
      }
    }
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var initialinmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data)
    var srcIp = initialinmsgipport[1];
    var srcPort = initialinmsgipport[2];
    var protocol = initialinmsgipport[3];
    var msg = initialinmsgipport[4];
    if (initialinmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var outmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data)
    //console.log(data + '\r\n');
    var dstIp = outmsgipport[1];
    var dstPort = outmsgipport[2];
    var protocol = outmsgipport[3];
    var msg = outmsgipport[4];
    if (outmsgipport[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outmsgipport[4]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (outmsgipport[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outmsgipport[4]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    }// else console.log();
    
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N  [0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) #012 #012 #012 \[[a-zA-Z0-9-_:@.]+\]/gm)) {
    var inoutmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N  [0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) #012 #012 #012 \[[a-zA-Z0-9-_:@.]+\]/gm.exec(data);
    //console.log(data + '\r\n');

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]/gm)) {
    var inmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]/gm.exec(data);
    //console.log(data + '\r\n');

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    //console.log(data + '\r\n');

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var initialinmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = initialinmsgipport[1];
    var srcPort = initialinmsgipport[2];
    var protocol = initialinmsgipport[3];
    var msg = initialinmsgipport[4];
    if (initialinmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }
    

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    //console.log(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\)\, [a-zA-Z]+\:[a-zA-Z]+\:[0-9]+\; \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\)\, [a-zA-Z]+\:[a-zA-Z]+\:[0-9]+\; \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [\w]+ TO\(#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    //console.log(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var initialinmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    //console.log(data);
    var srcIp = initialinmsgipport[1];
    var srcPort = initialinmsgipport[2];
    var protocol = initialinmsgipport[3];
    var msg = initialinmsgipport[4];
    if (initialinmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\)\, [a-zA-Z]+\:[a-zA-Z]+\:[0-9]+\; \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var initialinmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\)\, [a-zA-Z]+\:[a-zA-Z]+\:[0-9]+\; \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([\w]+) TO\(\#[0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = initialinmsgipport[1];
    var srcPort = initialinmsgipport[2];
    var protocol = initialinmsgipport[3];
    var msg = initialinmsgipport[4];
    if (initialinmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    //console.log(data);
    var msg = nodirectionmsglog[1];
    if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        var dstIp = dstipport[1];
        if (dstipport[2] !== undefined ) {
          var dstPort = dstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        var dstIp = dstipport[1];
        if (dstipport[2] !== undefined ) {
          var dstPort = dstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        (async () => {
          dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
            //console.log('addresses: ', addresses[0]);
            if(addresses !== undefined) {
              var dstIp = addresses[0];
              if (dstipport[2] !== undefined ) {
                var dstPort = dstipport[2];
              } else var dstPort = '5060';
              //console.log('srcIp: ', srcIp);
              //console.log('srcPort: ', srcPort);
              //console.log('dstIp: ', dstIp);
              //console.log('dstPort: ', dstPort);
              // start send packet to heplify-server
              if (msg) {
                var datenow = new Date().getTime();
                var time_sec = Math.floor(datenow / 1000);
                var time_usec = datenow - (time_sec*1000);
                var msg = msg.replace(/#012/gm, '\r\n')
                //var msg = msg + '\r\n';
                var rcinfo = { 
                  type: 'HEP',
                  version: 3,
                  payload_type: 'SIP',
                  captureId: hep_id,
                  capturePass: '',
                  ip_family: 2,
                  time_sec: time_sec,
                  time_usec: time_usec,
                  protocol: 6,
                  proto_type: 1,
                  srcIp: srcIp,
                  dstIp: dstIp,
                  srcPort: srcPort,
                  dstPort: srcPort 
                }
                sendHEP3(msg,rcinfo);
              }
              // stop send packet to heplify-server
            }
          });
        })()
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        (async () => {
          dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
            //console.log('addresses: ', addresses[0]);
            if(addresses !== undefined) {
              var dstIp = addresses[0];
              if (dstipport[2] !== undefined ) {
                var dstPort = dstipport[2];
              } else var dstPort = '5060';
              //console.log('srcIp: ', srcIp);
              //console.log('srcPort: ', srcPort);
              //console.log('dstIp: ', dstIp);
              //console.log('dstPort: ', dstPort);
              // start send packet to heplify-server
              if (msg) {
                var datenow = new Date().getTime();
                var time_sec = Math.floor(datenow / 1000);
                var time_usec = datenow - (time_sec*1000);
                var msg = msg.replace(/#012/gm, '\r\n')
                //var msg = msg + '\r\n';
                var rcinfo = { 
                  type: 'HEP',
                  version: 3,
                  payload_type: 'SIP',
                  captureId: hep_id,
                  capturePass: '',
                  ip_family: 2,
                  time_sec: time_sec,
                  time_usec: time_usec,
                  protocol: 6,
                  proto_type: 1,
                  srcIp: srcIp,
                  dstIp: dstIp,
                  srcPort: srcPort,
                  dstPort: srcPort 
                }
                sendHEP3(msg,rcinfo);
              }
              // stop send packet to heplify-server
            }
          });
        })()
      }
    } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      console.log('srcIp: ', srcIp);
      console.log('srcPort: ', srcPort);
      console.log('dstIp: ', dstIp);
      console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }
    }// else console.log();

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var msg = nodirectionmsglog[1];
    if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        var dstIp = dstipport[1];
        if (dstipport[2] !== undefined ) {
          var dstPort = dstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        var dstIp = dstipport[1];
        if (dstipport[2] !== undefined ) {
          var dstPort = dstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        (async () => {
          dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
            //console.log('addresses: ', addresses[0]);
            if(addresses !== undefined) {
              var dstIp = addresses[0];
              if (dstipport[2] !== undefined ) {
                var dstPort = dstipport[2];
              } else var dstPort = '5060';
              //console.log('srcIp: ', srcIp);
              //console.log('srcPort: ', srcPort);
              //console.log('dstIp: ', dstIp);
              //console.log('dstPort: ', dstPort);
              // start send packet to heplify-server
              if (msg) {
                var datenow = new Date().getTime();
                var time_sec = Math.floor(datenow / 1000);
                var time_usec = datenow - (time_sec*1000);
                var msg = msg.replace(/#012/gm, '\r\n')
                //var msg = msg + '\r\n';
                var rcinfo = { 
                  type: 'HEP',
                  version: 3,
                  payload_type: 'SIP',
                  captureId: hep_id,
                  capturePass: '',
                  ip_family: 2,
                  time_sec: time_sec,
                  time_usec: time_usec,
                  protocol: 6,
                  proto_type: 1,
                  srcIp: srcIp,
                  dstIp: dstIp,
                  srcPort: srcPort,
                  dstPort: srcPort 
                }
                sendHEP3(msg,rcinfo);
              }
              // stop send packet to heplify-server
            }
          });
        })()
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        (async () => {
          dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
            //console.log('addresses: ', addresses[0]);
            if(addresses !== undefined) {
              var dstIp = addresses[0];
              if (dstipport[2] !== undefined ) {
                var dstPort = dstipport[2];
              } else var dstPort = '5060';
              //console.log('srcIp: ', srcIp);
              //console.log('srcPort: ', srcPort);
              //console.log('dstIp: ', dstIp);
              //console.log('dstPort: ', dstPort);
              // start send packet to heplify-server
              if (msg) {
                var datenow = new Date().getTime();
                var time_sec = Math.floor(datenow / 1000);
                var time_usec = datenow - (time_sec*1000);
                var msg = msg.replace(/#012/gm, '\r\n')
                //var msg = msg + '\r\n';
                var rcinfo = { 
                  type: 'HEP',
                  version: 3,
                  payload_type: 'SIP',
                  captureId: hep_id,
                  capturePass: '',
                  ip_family: 2,
                  time_sec: time_sec,
                  time_usec: time_usec,
                  protocol: 6,
                  proto_type: 1,
                  srcIp: srcIp,
                  dstIp: dstIp,
                  srcPort: srcPort,
                  dstPort: srcPort 
                }
                sendHEP3(msg,rcinfo);
              }
              // stop send packet to heplify-server
            }
          });
        })()
      }
    } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[4] !== undefined) {
        if (nodirectionmsglog[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
          var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
          var dstIp = dstipport[1];
          if (dstipport[2] !== undefined ) {
            var dstPort = dstipport[2];
          } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
        }
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }
    }// else console.log();

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var msg = nodirectionmsglog[1];
    if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        var dstIp = dstipport[1];
        if (dstipport[2] !== undefined ) {
          var dstPort = dstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        var dstIp = dstipport[1];
        if (dstipport[2] !== undefined ) {
          var dstPort = dstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        (async () => {
          dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
            //console.log('addresses: ', addresses[0]);
            if(addresses !== undefined) {
              var dstIp = addresses[0];
              if (dstipport[2] !== undefined ) {
                var dstPort = dstipport[2];
              } else var dstPort = '5060';
              //console.log('srcIp: ', srcIp);
              //console.log('srcPort: ', srcPort);
              //console.log('dstIp: ', dstIp);
              //console.log('dstPort: ', dstPort);
              // start send packet to heplify-server
              if (msg) {
                var datenow = new Date().getTime();
                var time_sec = Math.floor(datenow / 1000);
                var time_usec = datenow - (time_sec*1000);
                var msg = msg.replace(/#012/gm, '\r\n')
                //var msg = msg + '\r\n';
                var rcinfo = { 
                  type: 'HEP',
                  version: 3,
                  payload_type: 'SIP',
                  captureId: hep_id,
                  capturePass: '',
                  ip_family: 2,
                  time_sec: time_sec,
                  time_usec: time_usec,
                  protocol: 6,
                  proto_type: 1,
                  srcIp: srcIp,
                  dstIp: dstIp,
                  srcPort: srcPort,
                  dstPort: srcPort 
                }
                sendHEP3(msg,rcinfo);
              }
              // stop send packet to heplify-server
            }
          });
        })()
      } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
        var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
        (async () => {
          dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
            //console.log('addresses: ', addresses[0]);
            if(addresses !== undefined) {
              var dstIp = addresses[0];
              if (dstipport[2] !== undefined ) {
                var dstPort = dstipport[2];
              } else var dstPort = '5060';
              //console.log('srcIp: ', srcIp);
              //console.log('srcPort: ', srcPort);
              //console.log('dstIp: ', dstIp);
              //console.log('dstPort: ', dstPort);
              // start send packet to heplify-server
              if (msg) {
                var datenow = new Date().getTime();
                var time_sec = Math.floor(datenow / 1000);
                var time_usec = datenow - (time_sec*1000);
                var msg = msg.replace(/#012/gm, '\r\n')
                //var msg = msg + '\r\n';
                var rcinfo = { 
                  type: 'HEP',
                  version: 3,
                  payload_type: 'SIP',
                  captureId: hep_id,
                  capturePass: '',
                  ip_family: 2,
                  time_sec: time_sec,
                  time_usec: time_usec,
                  protocol: 6,
                  proto_type: 1,
                  srcIp: srcIp,
                  dstIp: dstIp,
                  srcPort: srcPort,
                  dstPort: srcPort 
                }
                sendHEP3(msg,rcinfo);
              }
              // stop send packet to heplify-server
            }
          });
        })()
      }
    } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawsrcipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
      var srcIp = rawsrcipport[1];
      if (rawsrcipport[2] !== undefined ) {
        var srcPort = rawsrcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (nodirectionmsglog[1].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }
    }// else console.log();

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]+\.[\d]+\.[\d]+\.[\d]+\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]+\.[\d]+\.[\d]+\.[\d]+\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]+\.[\d]+\.[\d]+\.[\d]+\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]+\.[\d]+\.[\d]+\.[\d]+\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var srcIp = srcipport[1];
      var msg = nodirectionmsglog[1];
      if (srcipport[2] !== undefined ) {
        var srcPort = srcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      }
    } else if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(srcipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var srcIp = addresses[0];
            if (srcipport[2] !== undefined ) {
              var srcPort = srcipport[2];
            } else var srcPort = '5060';
            if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            }
          }
        });
      })()
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var initialinmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012(.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = initialinmsgipport[1];
    var srcPort = initialinmsgipport[2];
    var protocol = initialinmsgipport[3];
    var msg = initialinmsgipport[4];
    if (initialinmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    } else if (initialinmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(initialinmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inmsglog[1];
    var srcPort = inmsglog[2];
    var protocol = inmsglog[3];
    var msg = inmsglog[4];
    if (inmsglog[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inmsglog[4]);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
    } else if (inmsglog[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
      var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inmsglog[4]);
      var dstIp = rawdstipport[1];
      if (rawdstipport[2] !== undefined ) {
        var dstPort = rawdstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    }
  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip:.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inoutmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip:.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inoutmsglog[1];
    var srcPort = inoutmsglog[2];
    var protocol = inoutmsglog[3];
    var msg = inoutmsglog[4];
    if (inoutmsglog[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inoutmsglog[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
      var dstIp = inoutmsglog[5];
      var dstPort = inoutmsglog[6];
      var protocol = inoutmsglog[7];
      var msg = inoutmsglog[8];
      if (inoutmsglog[8] !== undefined) {
        if (inoutmsglog[8].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
          var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inoutmsglog[8]);
          var srcIp = rawdstipport[1];
          if (rawdstipport[2] !== undefined ) {
            var srcPort = rawdstipport[2];
          } else var srcPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
        } else if (inoutmsglog[8].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
          var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inoutmsglog[8]);
          var srcIp = rawdstipport[1];
          if (rawdstipport[2] !== undefined ) {
            var srcPort = rawdstipport[2];
          } else var srcPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
        }
      }
    } else if (inoutmsglog[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inoutmsglog[4]);

      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })()
      var dstIp = inoutmsglog[5];
      var dstPort = inoutmsglog[6];
      var protocol = inoutmsglog[7];
      var msg = inoutmsglog[8];
      if (inoutmsglog[8] !== undefined) {
        if (inoutmsglog[8].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
          var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inoutmsglog[8]);
          var srcIp = rawdstipport[1];
          if (rawdstipport[2] !== undefined ) {
            var srcPort = rawdstipport[2];
          } else var srcPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
        } else if (inoutmsglog[8].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
          var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inoutmsglog[8]);
          var srcIp = rawdstipport[1];
          if (rawdstipport[2] !== undefined ) {
            var srcPort = rawdstipport[2];
          } else var srcPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
        }
      }
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    //console.log(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var outmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var dstIp = outmsglog[1];
      var dstPort = outmsglog[2];
      var protocol = outmsglog[3];
      var msg = outmsglog[4];
      if (outmsglog[4] !== undefined) {
        if (outmsglog[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
          var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outmsglog[4]);
          var srcIp = rawdstipport[1];
          if (rawdstipport[2] !== undefined ) {
            var srcPort = rawdstipport[2];
          } else var srcPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
        } else if (outmsglog[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
          var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outmsglog[4]);
          var srcIp = rawdstipport[1];
          if (rawdstipport[2] !== undefined ) {
            var srcPort = rawdstipport[2];
          } else var srcPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
        }
      }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+ .*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+ .*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var srcIp = srcipport[1];
      var msg = nodirectionmsglog[1];
      if (srcipport[2] !== undefined ) {
        var srcPort = srcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      }
    } else if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(srcipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var srcIp = addresses[0];
            if (srcipport[2] !== undefined ) {
              var srcPort = srcipport[2];
            } else var srcPort = '5060';
            if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            }
          }
        });
      })()
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+ .*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+ .*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var srcIp = srcipport[1];
      var msg = nodirectionmsglog[1];
      if (srcipport[2] !== undefined ) {
        var srcPort = srcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      }
    } else if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(srcipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var srcIp = addresses[0];
            if (srcipport[2] !== undefined ) {
              var srcPort = srcipport[2];
            } else var srcPort = '5060';
            if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            }
          }
        });
      })()
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    if (inmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    //console.log(data + '\r\n');
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    if (inmsgipport[4] !== undefined) {
      if (inmsgipport[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inmsgipport[4]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (inmsgipport[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inmsgipport[4]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      }
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+.*) \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+.*) \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var msg = nodirectionmsglog[1];
    if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var srcIp = srcipport[1];
      if (srcipport[2] !== undefined ) {
        var srcPort = srcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      }
    } else if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(srcipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var srcIp = addresses[0];
            if (srcipport[2] !== undefined ) {
              var srcPort = srcipport[2];
            } else var srcPort = '5060';
            if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            }
          }
        });
      })()
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    if (inmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var outmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var dstIp = outmsglog[1];
    var dstPort = outmsglog[2];
    var protocol = outmsglog[3];
    var msg = outmsglog[4];
    if (outmsglog[4] !== undefined) {
      if (outmsglog[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outmsglog[4]);
        var srcIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var srcPort = rawdstipport[2];
        } else var srcPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (outmsglog[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(outmsglog[4]);
        var srcIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var srcPort = rawdstipport[2];
        } else var srcPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      }
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    //console.log(msg);
    if (inmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+.*) \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +([\w]+\/[0-9]+\.[0-9]+.*) \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      var srcIp = srcipport[1];
      var msg = nodirectionmsglog[1];
      if (srcipport[2] !== undefined ) {
        var srcPort = srcipport[2];
      } else var srcPort = '5060';
      if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      }
    } else if (nodirectionmsglog[1].match(/\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm)) {
      var srcipport = /\#012To: <sip:[a-zA-Z0-9-_]+?\@?([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+):?([0-9]+)?/gm.exec(nodirectionmsglog[1]);
      (async () => {
        dstIp = await resolver.resolve4(srcipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var srcIp = addresses[0];
            if (srcipport[2] !== undefined ) {
              var srcPort = srcipport[2];
            } else var srcPort = '5060';
            if (nodirectionmsglog[1].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            } else if (nodirectionmsglog[1].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
              var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(nodirectionmsglog[1]);
              var dstIp = rawdstipport[1];
              if (rawdstipport[2] !== undefined ) {
                var dstPort = rawdstipport[2];
              } else var dstPort = '5060';
                //console.log('srcIp: ', srcIp);
                //console.log('srcPort: ', srcPort);
                //console.log('dstIp: ', dstIp);
                //console.log('dstPort: ', dstPort);
                // start send packet to heplify-server
                if (msg) {
                  var datenow = new Date().getTime();
                  var time_sec = Math.floor(datenow / 1000);
                  var time_usec = datenow - (time_sec*1000);
                  var msg = msg.replace(/#012/gm, '\r\n')
                  //var msg = msg + '\r\n';
                  var rcinfo = { 
                    type: 'HEP',
                    version: 3,
                    payload_type: 'SIP',
                    captureId: hep_id,
                    capturePass: '',
                    ip_family: 2,
                    time_sec: time_sec,
                    time_usec: time_usec,
                    protocol: 6,
                    proto_type: 1,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: srcPort 
                  }
                  sendHEP3(msg,rcinfo);
                }
                // stop send packet to heplify-server
            }
          }
        });
      })()
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\)\, [\w]+\:[\w]+\:[0-9]+\; \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]/gm)) {
    var inmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by Address\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\)\, [\w]+\:[\w]+\:[0-9]+\; \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]/gm.exec(data);
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    //console.log(msg);
    if (inmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    }

  } else if (data.match(/[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsgipport = /[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    //console.log(msg);
    if (inmsgipport[4].match(/[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_]+\@([\d]+\.[\d]+\.[\d]+\.[\d]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      var dstIp = dstipport[1];
      if (dstipport[2] !== undefined ) {
        var dstPort = dstipport[2];
      } else var dstPort = '5060';
      //console.log('srcIp: ', srcIp);
      //console.log('srcPort: ', srcPort);
      //console.log('dstIp: ', dstIp);
      //console.log('dstPort: ', dstPort);
      // start send packet to heplify-server
      if (msg) {
        var datenow = new Date().getTime();
        var time_sec = Math.floor(datenow / 1000);
        var time_usec = datenow - (time_sec*1000);
        var msg = msg.replace(/#012/gm, '\r\n')
        //var msg = msg + '\r\n';
        var rcinfo = { 
          type: 'HEP',
          version: 3,
          payload_type: 'SIP',
          captureId: hep_id,
          capturePass: '',
          ip_family: 2,
          time_sec: time_sec,
          time_usec: time_usec,
          protocol: 6,
          proto_type: 1,
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: srcPort,
          dstPort: srcPort 
        }
        sendHEP3(msg,rcinfo);
      }
      // stop send packet to heplify-server
    } else if (inmsgipport[4].match(/[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    } else if (inmsgipport[4].match(/[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm)) {
      var dstipport = /[\w]+ sip\:\+?[a-zA-Z0-9-_+]+\@([a-zA-Z-_]+\.[a-zA-Z0-9-_.]+)\:?([0-9]+)?/gm.exec(inmsgipport[4]);
      (async () => {
        dstIp = await resolver.resolve4(dstipport[1], (err, addresses) => {
          //console.log('addresses: ', addresses[0]);
          if(addresses !== undefined) {
            var dstIp = addresses[0];
            if (dstipport[2] !== undefined ) {
              var dstPort = dstipport[2];
            } else var dstPort = '5060';
            //console.log('srcIp: ', srcIp);
            //console.log('srcPort: ', srcPort);
            //console.log('dstIp: ', dstIp);
            //console.log('dstPort: ', dstPort);
            // start send packet to heplify-server
            if (msg) {
              var datenow = new Date().getTime();
              var time_sec = Math.floor(datenow / 1000);
              var time_usec = datenow - (time_sec*1000);
              var msg = msg.replace(/#012/gm, '\r\n')
              //var msg = msg + '\r\n';
              var rcinfo = { 
                type: 'HEP',
                version: 3,
                payload_type: 'SIP',
                captureId: hep_id,
                capturePass: '',
                ip_family: 2,
                time_sec: time_sec,
                time_usec: time_usec,
                protocol: 6,
                proto_type: 1,
                srcIp: srcIp,
                dstIp: dstIp,
                srcPort: srcPort,
                dstPort: srcPort 
              }
              sendHEP3(msg,rcinfo);
            }
            // stop send packet to heplify-server
          }
        });
      })();
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sips\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sips\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sips\:.*) #012 #012 #012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sips\:.*) #012 #012 #012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var inmsgipport = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);
    var srcIp = inmsgipport[1];
    var srcPort = inmsgipport[2];
    var protocol = inmsgipport[3];
    var msg = inmsgipport[4];
    if (inmsgipport[4] !== undefined) {
      if (inmsgipport[4].match(/\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012Via\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inmsgipport[4]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
          //console.log('srcIp: ', srcIp);
          //console.log('srcPort: ', srcPort);
          //console.log('dstIp: ', dstIp);
          //console.log('dstPort: ', dstPort);
          // start send packet to heplify-server
          if (msg) {
            var datenow = new Date().getTime();
            var time_sec = Math.floor(datenow / 1000);
            var time_usec = datenow - (time_sec*1000);
            var msg = msg.replace(/#012/gm, '\r\n')
            //var msg = msg + '\r\n';
            var rcinfo = { 
              type: 'HEP',
              version: 3,
              payload_type: 'SIP',
              captureId: hep_id,
              capturePass: '',
              ip_family: 2,
              time_sec: time_sec,
              time_usec: time_usec,
              protocol: 6,
              proto_type: 1,
              srcIp: srcIp,
              dstIp: dstIp,
              srcPort: srcPort,
              dstPort: srcPort 
            }
            sendHEP3(msg,rcinfo);
          }
          // stop send packet to heplify-server
      } else if (inmsgipport[4].match(/\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm)) {
        var rawdstipport = /\#012v\: [A-Z]+\/[0-9]+\.[0-9]+\/[A-Z]+ ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:?[0-9]+?;/gm.exec(inmsgipport[4]);
        var dstIp = rawdstipport[1];
        if (rawdstipport[2] !== undefined ) {
          var dstPort = rawdstipport[2];
        } else var dstPort = '5060';
        //console.log('srcIp: ', srcIp);
        //console.log('srcPort: ', srcPort);
        //console.log('dstIp: ', dstIp);
        //console.log('dstPort: ', dstPort);
        // start send packet to heplify-server
        if (msg) {
          var datenow = new Date().getTime();
          var time_sec = Math.floor(datenow / 1000);
          var time_usec = datenow - (time_sec*1000);
          var msg = msg.replace(/#012/gm, '\r\n')
          //var msg = msg + '\r\n';
          var rcinfo = { 
            type: 'HEP',
            version: 3,
            payload_type: 'SIP',
            captureId: hep_id,
            capturePass: '',
            ip_family: 2,
            time_sec: time_sec,
            time_usec: time_usec,
            protocol: 6,
            proto_type: 1,
            srcIp: srcIp,
            dstIp: dstIp,
            srcPort: srcPort,
            dstPort: srcPort 
          }
          sendHEP3(msg,rcinfo);
        }
        // stop send packet to heplify-server
      }
    }

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+ from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) \-\-\-\- \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\ \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012\ \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[BID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[BID=[a-zA-Z0-9:]+\] +([\w]+ sip\:.*) \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[BID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[BID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N [0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012\(N [0-9]+\) \(\#[0-9]+\)Route found \([0-9]+\)\, Route by IPGroup\, IP Group [0-9]+ \-\> [0-9]+ \([a-zA-Z0-9-_:&]+ \-\> [a-zA-Z0-9-_:&]+\) \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Outgoing SIP Message to ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\:[0-9]+) from SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) ([A-Z]+) TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+ sip\:.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  } else if (data.match(/^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm)) {
    var nodirectionmsglog = /^[\w]{3} +\d{1,2} [\d:]{8} +[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3} +\[S=\d+\] +\[SID=[a-zA-Z0-9:]+\] +\(N +[0-9]+\) \-\-\-\- Incoming SIP Message from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\:([0-9]+) to SIPInterface \#[0-9]+ \([a-zA-Z0-9-_:&]+\) [A-Z]+ TO\(\#[0-9]+\) SocketID\([0-9]+\) \-\-\-\- \#012([\w]+\/[0-9]+\.[0-9]+.*) \#012 \#012 \#012 \[[a-zA-Z0-9-_:@.]+\]$/gm.exec(data);

  //} else if (data.match(//gm)) {
    //var nodirectionmsglog = //gm.exec(data);

  }// else console.log(data + '\r\n');
});

tail.on('error', (err) => {
  console.log(err + '\r\n');
  console.log(`Process will exit with code: 1`)
    process.exit('1')
})
