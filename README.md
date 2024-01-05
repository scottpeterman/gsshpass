# gsshpass Network Automation

This utility is a powerful tool for network automation, enabling remote command execution over SSH on network devices. It's built in Go and provides a flexible and efficient way to manage network configurations and operations.

## Features

- **Windows Support**: Should work on any platform Go compiles on, including windows
- **SSH-Based Command Execution**: Connect to devices using SSH and execute commands remotely.
- **Interactive Shell Support**: Option to invoke an interactive shell on the remote device for complex command sequences.
- **Customizable SSH Configuration**: Supports setting various SSH parameters like ciphers, key exchanges, and host key algorithms.
- **Prompt Recognition**: Ability to recognize custom prompts in interactive sessions, useful for script automation in varied environments.
- **Timeout Handling**: Configurable command execution timeout to handle unresponsive sessions. The timeout error message now includes the count of prompts seen to assist in debugging and script tuning.
- **Single/Multiple Command Execution**: Ability to run multiple commands in a sequence, either in a shell session or single individual SSH commands without a shell.
- **Intercommand Delay**: Set a delay between the execution of commands to accommodate slower responding devices.
- **Command File Input**: Option to use a command file instead of command-line input for executing a sequence of commands, providing an alternative for complex automation tasks.

## CLI Arguments

- `-h`: SSH Host in the format `ip:port`. Example: `192.168.1.1:22`.
- `-u`: SSH Username for authentication.
- `-p`: SSH Password for authentication.
- `-c`: Commands to run, separated by commas. Example: `show running-config,show ip interface brief`.
- `--invoke-shell`: Boolean flag to invoke shell before running the command. Useful for interactive commands.
- `--prompt`: Custom prompt to look for in interactive shell mode. Useful to identify when to send the next command.
- `--prompt-count`: Number of times the custom prompt is matched before concluding command execution in shell mode.
- `-t`: Timeout duration in seconds for command execution. Helps prevent hanging sessions.
- `--ciphers`: Comma-separated list of SSH ciphers. Example: `aes128-ctr,aes192-ctr`.
- `--kex`: Comma-separated list of SSH key exchange algorithms.
- `--hostkeyalgos`: Comma-separated list of SSH host key algorithms.
- `--intercommand-delay`: Delay in seconds between each command. Default is 1 second.
- `--command-file`: File path for a file containing a list of commands to be executed.

## Usage

Compile the utility and run it using the appropriate flags. For example:

```shell
./gsshpass -h 192.168.1.1:22 -u admin -p password -c "term len 0,show version,show interfaces" --invoke-shell --prompt "Router#" --prompt-count 3 -t 30
```

This command connects to a router at `192.168.1.1` on port `22`, logs in with username `admin` and password `password`, then executes `show version` and `show interfaces` in an interactive shell session, waiting for the custom prompt `Router#` three times before concluding each command, with a timeout of 30 seconds.

For a sequence of commands with delays, you might use:

```shell
./gsshpass -h "192.168.1.1:22" -u "cisco" -p "cisco" -c "configure terminal,interface GigabitEthernet0/1,description Link to Router,,," --invoke-shell --prompt "#" --prompt-count 2 --intercommand-delay 2
```

This command configures an interface description on a Cisco device, with a 2-second delay between each command, and expects to see the "#" prompt twice before concluding the session.

Alternatively, to use a command file:

```shell
./gsshpass -h "192.168.1.1:22" -u "cisco" -p "cisco" --command-file "router_commands.txt"
```

###     Here is an example command text file:

``` 
configure terminal
banner motd #
ASCII Art:
TCP Header:
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |        Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Offset|  Res. |     Flags     |             Window            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Checksum           |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Terms of Use:
Unauthorized access is prohibited. Usage is subject to security testing and monitoring. Misuse is subject to criminal prosecution.
#
```
This will execute a series of commands listed in `router_commands.txt` on the Cisco device.

## Building from Source

Ensure you have Go installed and run:

```shell
go build -o gsshpass.exe
```

This will compile the source code into an executable named `gsshpass.exe`.

## via go get
```shell
go get github.com/scottpeterman/gsshpass@v0.1.0-beta.1

```
## Error Reporting

In case of a timeout due to an insufficient number of prompts, the error message will now include the actual count of prompts seen. This aids in adjusting the `--prompt-count` for subsequent executions.


