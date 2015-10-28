# dmrshark

dmrshark analyses the traffic, and adds extra features to a Hytera IPSC network.

It can be used for:

- Tracking and decoding voice calls, logging to a text file, and/or inserting them to a remote MySQL-compatible database.
- Saving raw AMBE and decoded voice data to raw or MP3 files.
- Streaming voice calls as plain HTTP MP3 streams or Websocket MP3 streams.
- Playing back previously recorded AMBE voice files to repeaters.
- Echo service.
- Measure actual and average RMS volume of the calls, and upload them to a remote database, so users can adjust their mic gain settings.
- Sends average RMS volume and average RSSI as an SMS after an echo test.
- Automatic and periodic reading of repeater timeslot RSSI values during calls and also inserting them to the remote database.
- Updating a remote database table with currently active repeaters and their info (ul/dl freqs, type, fw version etc.).
- Receiving and sending DMR SMS messages (both in standard DMR and Motorola TMS format) from/to SQL database tables.
- SMS command interface (see the explanation below).
- Decoding Hytera GPS position (including speed and course) messages with error correction and acking.
- Uploading received GPS position information to APRS.
- Uploading predefined APRS objects (for repeaters or other fixed locations).

For optimal network traffic analysis, it should run on the server machine which is running the master software (DMRplus, lindmrmaster etc.),
however, it can be run on a machine which only has a few (or one) repeater's traffic passing by.

Contact:

- Norbert "Nonoo" Varga, HA2NON [nonoo@nonoo.hu](mailto:nonoo@nonoo.hu)
- [nonoo.hu](http://nonoo.hu)
- [ham-dmr.hu](http://ham-dmr.hu)

## Compiling

You'll need to have the following libs installed on your system to compile dmrshark:

- libglib2.0-dev / glib2-devel
- libpcap-dev / libpcap-devel
- libsnmp-dev / net-snmp-devel
- libmysqlclient-dev / mariadb-devel
- [libwebsockets](https://libwebsockets.org/)
- [mbelib](https://github.com/szechyjs/mbelib) (optional)
- libmp3lame-dev (optional)

Instructions on compiling and installing:

```
git clone https://github.com/nonoo/dmrshark.git
cd dmrshark/build/dmrshark
make
make install
```

Now you will have dmrshark installed to **/opt/dmrshark**.

### libmbe

If you don't want to use libmbe, create **Makefile.config.inc** in the dmrshark source root directory, and add the following:

```
AMBEDECODEVOICE := 0
```

### libmp3lame

If you don't want to use libmp3lame, create **Makefile.config.inc** in the dmrshark source root directory, and add the following:

```
MP3ENCODEVOICE := 0
```

## Configuration

dmrshark.cfg and it's missing configuration variables will be automatically generated on dmrshark startup.
If you want to set a variable back to it's default value, just erase it's line and restart dmrshark.

The file has the following configuration variables:

- **loglevel**: Numeric representation of the loglevel. It can be changed using the console command **log**.
- **logfile**: This is the file where dmrshark will log to.
- **pidfile**: This file will be created on startup, the running dmrshark process PID will be written to it.
- **daemonctlfile**: This is the UNIX socket file which will be used for communicating with dmrshark's remote console server.
- **ttyconsoledev**: dmrshark's console can also be outputted to a serial port defined here.
- **ttyconsoleenabled**: Write 1 here to enable the serial console.
- **ttyconsolebaudrate**: Baud rate to use on the serial console.
- **netdevicename**: Interface for libpcap to listen on. Set it to **any**, this will make libpcap to listen on all passing traffic.
- **repeaterinfoupdateinsec**: Interval in seconds to update repeater info (ul/dl freqs, type, fw version etc.) using SNMP. Enter 0 here to disable this feature.
- **repeaterinactivetimeoutinsec**: If no heartbeat is received within this period, the repeater will be considered offline.
- **rssiupdateduringcallinmsec**: Period in msec to update repeater timeslot RSSI info using SNMP. Enter 0 here to disable this feature.
- **calltimeoutinsec**: If the voice call terminating packet is missing, dmrshark will time out the call after the last voice packet received plus this many seconds.
- **datatimeoutinsec**: Max. time of a data transmission. Timeout counting starts when the first packet (header) is received.
- **ignoredsnmprepeaterhosts**: You can enter the host names or IP addresses of repeaters which should not be queried using SNMP.
  If dmrshark is not running on the server where the master software is running, the master software will show up as a repeater in
  the repeater list. To avoid starting SNMP queries to the master software's machine, add it's host/IP here. Separate each entry
  with a comma.
- **remotedbhost**: Remote database host. If you want to disable the remote database function, leave this empty.
- **remotedbuser**: Remote database user.
- **remotedbpass**: Remote database password.
- **remotedbname**: Remote database name.
- **remotedbtableprefix**: Remote database table prefix.
- **userdbtablename**: Table to get DMR ID and callsign associations from. This is used when retransmitting messages and when the info command is used. Set to empty to disable.
- **callsignbookdbtablename**: Table to get callsign book data from. This is used when answering the info command. Set to empty to disable.
- **remotedbreconnecttrytimeoutinsec**: If the remote database connection gets lost, dmrshark will try to reconnect in this interval.
- **remotedbdeleteolderthansec**: Clear remote database log entries older than this many seconds.
- **remotedbuserlistdlperiodinsec**: Update user list in this interval. Set it to 0 to disable user list download.
- **remotedbmaintenanceperiodinsec**: Maintenance (deleting of old entries) will happen in this interval.
- **remotedbmsgqueuepollintervalinsec**: Check for messages to send in the remote DB message queue. Set to 0 to disable.
- **repeaterinfoupdateinsec**: Active repeaters will be queried for status in this interval.
- **updatestatstableenabled**: Enter 1 here, if you want the repeater stats table to be updated when a heartbeat packet is received.
- **ignoredhosts**: Ignore IP packets coming from these hosts (separated by commas).
- **allowedtalkgroups**: Allow these dst talk groups during IPSC packet processing (separated by commas). Wildcard "*" allows all talkgroups.
- **ignoredtalkgroups**: Ignore these dst talk groups during IPSC packet processing (separated by commas). Wildcard "*" disallows all talkgroups which are not previously allowed.
- **httpserverenabled**: Set this to 1 to enable built-in HTTP/Websockets server, which is needed for streaming.
- **httpserverport**: Port to bind the HTTP/Websockets server.
- **masteripaddr**: Set this to the IP address of the DMR master software. This IP will be the source address for outgoing dmrshark packets to the repeaters.
- **smssendmaxretrycount**: Retry SMS sending from the SMS TX buffer this many times.
- **mindatapacketsendretryintervalinsec**: Retry sending data (including SMS) packets in this interval. SMSes are added to the SMS TX buffer for the first time, then the buffer adds them to the data packet TX buffer for transmitting.
- **datapacketsendmaxretrycount**: Retry sending data packets (including SMS) this many times.
- **smsretransmittimeoutinsec**: Retransmit Motorola TMS as normal SMS and vica versa after this many seconds of the last successful receive. Set to 0 to disable retransmitting.
- **aprsserverhost**: APRS server host. Set it to empty to disable APRS GPS position upload.
- **aprsserverport**: APRS server port.
- **aprsservercallsign**: dmrshark sysop callsign.
- **aprsserverpasscode**: APRS passcode for the dmrshark sysop callsign.

The needed remote database table structures can be found [here](https://github.com/nonoo/dmrshark-wordpress-plugin/blob/master/example.sql) and [here](https://github.com/nonoo/ha5kdr-dmr-db/blob/master/example.sql).

## Configuring voice streams

You can define voice streams as .ini structure groups. Example:

```
[stream-hg5ruc-ts1]
enabled=1
repeaterhosts=1.2.3.4,repeater123.nonoo.hu
savefiledir=
savetorawambefile=1
savedecodedtorawfile=1
savedecodedtomp3file=1
minmp3bitrate=32
mp3bitrate=64
mp3quality=0
mp3vbr=0
timeslot=1
decodequality=3
playrawfileatcallstart=call-start.raw
rawfileatcallstartgain=0.1
playrawfileatcallend=call-end.raw
rawfileatcallendgain=0.1

[stream-hg5ruc-ts2]
enabled=1
repeaterhosts=*
...
```

You can define as many voice streams as you want.
Voice stream configure variables:

- **enabled**: 0 if voice stream is disabled, 1 if enabled.
- **repeaterhosts**: Host names/IP addresses of the repeaters which are the sources of the stream. You can use the "*" wildcard to match all hosts.
- **timeslot**: Timeslot of the repeater which we want to process.
- **savefiledir**: Captured voice files will be saved to this directory. If empty, files will be saved to the current directory.
- **savetorawambefile**: Set this to 1 if you want to save raw AMBE2+ voice data.
- **savedecodedtorawfile**: Set this to 1 if you want to save raw, but decoded voice data. Samples are saved as 8kHz IEEE 32bit floats.
- **savedecodedtomp3file**: Set this to 1 if you want to save decoded and streamed voice data in MP3 files.
- **minmp3bitrate**: Minimum bitrate of the MP3 encoder in VBR mode.
- **mp3bitrate**: Bitrate of the MP3 encoder (max. bitrate in VBR mode).
- **mp3quality**: Quality of MP3 encoding. 0 - highest, 9 - lowest.
- **mp3vbr**: Set this to 1 to enable VBR encoding mode.
- **decodequality**: Quality of AMBE2+ decoding, valid values are between 1 and 64, 1 is the worst and 64 is the best quality. Default value is 3. Note that increasing decoding quality increases used CPU time.
- **playrawfileatcallstart**: Plays this raw wave file at the start of a call. Sample format is 8kHz IEEE 32bit float.
- **rawfileatcallstartgain**: This gain (0.0-1.0) will be applied for the file to play at call start.
- **playrawfileatcallend**: Plays this raw wave file at the end of a call. Sample format is 8kHz IEEE 32bit float.
- **rawfileatcallendgain**: This gain (0.0-1.0) will be applied for the file to play at call end.
- **rmsminsamplevalue**: Minimum float value of the decoded voice stream to calculate RMS for. This is used for ignoring silence during RMS calculation.

## APRS objects

You can define APRS objects to send to APRS-IS and so place them on the APRS map. They have to be .ini format groups defined in the config file. The group name contains the callsign. Example:

```
[aprsobj-hg5ruc]
enabled=1
latitude=4730.06
latitude-ch=N
longitude=01858.39
longitude-ch=E
description=Hytera RD985 438.5MHz / dmrshark / ham-dmr.hu
table-ch=/
symbol-ch=r

[aprsobj-ha5kdr]
enabled=1
latitude=4730.08
latitude-ch=N
longitude=01858.38
longitude-ch=E
description=Budapest Fovarosi Radioamator Klub QTH - ha5kdr.hu
table-ch=/
symbol-ch=-
...
```

You can define as many APRS objects as you want.
APRS object configure variables:

- **enabled**: 1 if entry is enabled, 0 if disabled.
- **latitude**: Latitude in degrees.
- **latitude-ch**: Latitude North or South.
- **longitude**: Longitude in degrees.
- **longitude-ch**: Longitude East or West.
- **description**: Object description.
- **table-ch**: APRS symbol table selector. See [this](http://wa8lmf.net/aprs/APRS_symbols.htm) page ([this](http://wa8lmf.net/miscinfo/APRS_Symbol_Chart_Rev-H.pdf) PDF).
- **symbol-ch**: APRS symbol character.

## Running

If dmrshark is started without an argument, it will fork into the background. Use **-f** to have dmrshark run in the foreground.
You can connect to a running process using the remote console, whether it's running in the foreground or the background by using the **-r** command line parameter.

If you are on the console, enter the command **help** or **h** to get the list of available commands.

For displaying the live log and repeater info tables on a webpage, you can use the [dmrshark Wordpress plugin](https://github.com/nonoo/dmrshark-wordpress-plugin). You can see a working example [here](http://ham-dmr.hu/elo-statusz/) or [here](http://live.ham-dmr.hu/).

## Command interface

The first word of the message sent to dmrshark's DMR ID (7777) is a command. Currently these are supported:

- **help**: Sends back the list of available commands.
- **info**: Send the DMR ID or the callsign of the user as the 2nd word, dmrshark will send you info about the callsign.
- **ping**: Sends back the text "pong".
- If the first word of the message is an email address, the message will be put into the MySQL database from where it can be sent as an email.

## Echo service

If you send voice to dmrshark's ID (7777), it will play it back and send average volume and RSSI info as a message after playback. Both private and group calls are supported on both timeslots.
Average volume and RSSI info message is also sent after standard DMRplus echo service calls (TS2/TG9990).
