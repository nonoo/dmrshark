# dmrshark

dmrshark uses libpcap to analyse the traffic of a Hytera IPSC network.

It can be used for:

- Tracking and decoding voice calls, measuring RMS volume, logging to a text file, and/or inserting them to a remote MySQL-compatible database.
- Saving decoded voice data to raw or MP3 files.
- Automatic and periodic reading of repeater timeslot RSSI values during calls and also inserting them to the remote database.
- Updating a remote database table with currently active repeaters and their info (ul/dl freqs, type, fw version etc.).
- Decoding DMR SMS messages.

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
- **remotedbreconnecttrytimeoutinsec**: If the remote database connection gets lost, dmrshark will try to reconnect in this interval.
- **remotedbdeleteolderthansec**: Clear remote database log entries older than this many seconds.
- **remotedbmaintenanceperiodinsec**: Maintenance (deleting of old entries) will happen in this interval.
- **repeaterinfoupdateinsec**: Active repeaters will be queried for status in this interval.
- **updatestatstableenabled**: Enter 1 here, if you want the repeater stats table to be updated when a heartbeat packet is received.
- **ignoredhosts**: Ignore IP packets coming from these hosts (separated by commas).

The needed remote database table structures can be found [here](https://github.com/nonoo/dmrshark-wordpress-plugin/blob/master/example.sql).

## Configuring voice streams

You can also define voice streams as .ini structure groups. Example:

```
[stream-hg5ruc-ts1]
enabled=1
repeaterhosts=1.2.3.4,repeater123.nonoo.hu
savefiledir=
savetorawfile=1
savedecodedtorawfile=1
savedecodedtomp3file=1
minmp3bitrate=32
mp3bitrate=64
mp3quality=0
mp3vbr=0
timeslot=1
decodequality=3
playrawfileatcallstart=call-start.raw
playrawfileatcallend=call-end.raw

[stream-hg5ruc-ts2]
enabled=1
repeaterhosts=*
savefiledir=
savetorawfile=1
savedecodedtorawfile=1
savedecodedtomp3file=1
minmp3bitrate=32
mp3bitrate=64
mp3quality=0
mp3vbr=0
timeslot=2
decodequality=64
playrawfileatcallstart=call-start.raw
playrawfileatcallend=call-end.raw
```

You can define as many voice streams as you want.
Voice stream configure variables:

- **enabled**: 0 if voice stream is disabled, 1 if enabled.
- **repeaterhosts**: Host names/IP addresses of the repeaters which are the sources of the stream. You can use the "*" wildcard to match all hosts.
- **timeslot**: Timeslot of the repeater which we want to process.
- **savefiledir**: Captured voice files will be saved to this directory. If empty, files will be saved to the current directory.
- **savetorawfile**: Set this to 1 if you want to save raw AMBE2+ voice data.
- **savedecodedtorawfile**: Set this to 1 if you want to save raw, but decoded voice data. Samples are saved as 8kHz IEEE 32bit floats.
- **savedecodedtomp3file**: Set this to 1 if you want to save decoded and streamed voice data in MP3 files.
- **minmp3bitrate**: Minimum bitrate of the MP3 encoder in VBR mode.
- **mp3bitrate**: Bitrate of the MP3 encoder (max. bitrate in VBR mode).
- **mp3quality**: Quality of MP3 encoding. 0 - highest, 9 - lowest.
- **mp3vbr**: Set this to 1 to enable VBR encoding mode.
- **decodequality**: Quality of AMBE2+ decoding, valid values are between 1 and 64, 1 is the worst and 64 is the best quality. Default value is 3. Note that increasing decoding quality increases used CPU time.
- **playrawfileatcallstart**: Plays this raw wave file at the start of a call. Sample format is 8kHz IEEE 32bit float.
- **playrawfileatcallend**: Plays this raw wave file at the end of a call. Sample format is 8kHz IEEE 32bit float.

## Running

If dmrshark is started without an argument, it will fork into the background. Use **-f** to have dmrshark run in the foreground.
You can connect to a running process using the remote console, whether it's running in the foreground or the background by using the **-r** command line parameter.

If you are on the console, enter the command **help** or **h** to get the list of available commands.

For displaying the live log and repeater info tables on a webpage, you can use the [dmrshark Wordpress plugin](https://github.com/nonoo/dmrshark-wordpress-plugin). You can see a working example [here](http://ham-dmr.hu/elo-statusz/) or [here](http://live.ham-dmr.hu/).
