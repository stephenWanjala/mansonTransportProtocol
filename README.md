# MTP 
MTP is a simple file transfer protocol implemented in Python using UDP sockets. This protocol ensures reliable and ordered delivery of data packets between a sender and a receiver over an unreliable network.

### Features
* Reliable data transmission using packet acknowledgments (ACKs)
* Ordered delivery of data packets
* Error detection using CRC32 checksums
* Adjustable window size for flow control
* Log file generation for monitoring protocol events
#### Usage
##### MTPSender
The MTPSender program sends a file to a receiver using MTP.

### Usage:

```bash
./MTPSender <receiver-IP> <receiver-port> <window-size> <input-file> <sender-log-file>
```
`<receiver-IP>:` IP address of the MTPReceiver.
`<receiver-port>:` Port number of the MTPReceiver.
`<window-size>:` Size of the sliding window for flow control.
`<input-file>:` Path to the input file to be sent.
`<sender-log-file>:` Path to the log file to log sender events.
Example:

```bash
Copy code
./MTPSender 127.0.0.1 12345 10 input.txt sender-log.txt
```

#### MTPReceiver
The MTPReceiver program receives a file from a sender using MTP.

##### Usage:

```bash
./MTPReceiver <receiver-port> <output-file> <receiver-log-file>
```

`<receiver-port>:` Port number on which the receiver is listening.
`<output-file>:` Path to the output file to store received data.
`<receiver-log-file>:` Path to the log file to log receiver events.
##### Example:

```bash
./MTPReceiver 12345 output.txt receiver-log.txt
```

##### Dependencies
    Python 3.x
    Additional Python libraries: None
##### License
This project is licensed under the [MIT License](LICENSE). - see the LICENSE file for details.