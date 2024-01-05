package main

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"strings"
	"time"
)

// SSHClientConfig holds the SSH client configuration.
type SSHClientConfig struct {
	Host              string
	User              string
	Password          string
	Cmds              []string
	InvokeShell       bool
	Prompt            string
	PromptCount       int
	Timeout           int
	Ciphers           []string
	KeyExchanges      []string
	HostKeyAlgos      []string
	IntercommandDelay int
}

// SSHClient interface for SSH operations
type SSHClient interface {
	Dial(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error)
}

// RealSSHClient is the real implementation that interacts with an actual SSH server
type RealSSHClient struct{}

func (c *RealSSHClient) Dial(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial(network, addr, config)
}

// ExecuteSSHCommands handles the SSH connection and command execution.
func ExecuteSSHCommands(client SSHClient, config SSHClientConfig) (string, error) {
	var promptCountSeen int // Variable to store the number of detected prompts

	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i, question := range questions {
					if strings.Contains(strings.ToLower(question), "password") {
						answers[i] = config.Password
					}
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(config.Timeout) * time.Second,
		Config: ssh.Config{
			Ciphers:      config.Ciphers,
			KeyExchanges: config.KeyExchanges,
		},
		HostKeyAlgorithms: config.HostKeyAlgos,
	}

	sshClient, err := client.Dial("tcp", config.Host, sshConfig)
	if err != nil {
		return "", fmt.Errorf("failed to dial: %w", err)
	}
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var output string

	if config.InvokeShell {

		if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
			return "", fmt.Errorf("request for pseudo terminal failed: %w", err)
		}

		stdinPipe, err := session.StdinPipe()
		if err != nil {
			return "", fmt.Errorf("failed to get stdin pipe: %w", err)
		}
		stdoutPipe, err := session.StdoutPipe()
		if err != nil {
			return "", fmt.Errorf("failed to get stdout pipe: %w", err)
		}

		err = session.Shell()
		if err != nil {
			return "", fmt.Errorf("failed to start shell: %w", err)
		}

		done := make(chan bool)
		timeout := time.After(time.Duration(config.Timeout) * time.Second)

		go func() {
			reader := bufio.NewReader(stdoutPipe)
			counter := 0
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					done <- false
					break
				}
				output += line
				if strings.Contains(line, config.Prompt) {
					promptCountSeen++ // Increment the prompt count

					counter++
					if counter >= config.PromptCount {
						done <- true
						break
					}
				}
			}
		}()

		for _, cmd := range config.Cmds {
			fmt.Fprintf(stdinPipe, "%s\n", cmd)
			time.Sleep(time.Duration(config.IntercommandDelay) * time.Second) // Adjusted delay
		}

		select {
		case <-done:
		case <-timeout:
			//return output, fmt.Errorf("execution timed out")
			return output, fmt.Errorf("execution timed out, prompt count seen: %d", promptCountSeen)

		}

		stdinPipe.Write([]byte("exit\n"))
	} else {
		for _, cmd := range config.Cmds {
			cmdOutput, err := session.CombinedOutput(cmd)
			if err != nil {
				return "", fmt.Errorf("failed to run command '%s': %w", cmd, err)
			}
			output += string(cmdOutput) + "\n"
			time.Sleep(time.Duration(config.IntercommandDelay) * time.Second) // Adjusted delay
		}
	}

	return output, nil
}

func readCommandsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var commands []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		commands = append(commands, scanner.Text())
	}

	return commands, scanner.Err()
}

func main() {
	host := flag.String("h", "", "SSH Host (ip:port)")
	user := flag.String("u", "", "SSH Username")
	password := flag.String("p", "", "SSH Password")
	cmds := flag.String("c", "", "Commands to run, separated by comma")
	invokeShell := flag.Bool("invoke-shell", false, "Invoke shell before running the command")
	prompt := flag.String("prompt", "", "Prompt to look for before breaking the shell")
	promptCount := flag.Int("prompt-count", 1, "Number of prompts to look for before breaking the shell")
	timeoutDuration := flag.Int("t", 10, "Command timeout duration in seconds")
	ciphers := flag.String("ciphers", "aes128-ctr,aes192-ctr,aes256-ctr,3des-cbc", "SSH Ciphers")
	keyExchanges := flag.String("kex", "curve25519-sha256@libssh.org,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1", "SSH Key Exchange Algorithms")
	hostKeyAlgos := flag.String("hostkeyalgos", "ssh-rsa", "SSH Host Key Algorithms")
	intercommandDelay := flag.Int("intercommand-delay", 1, "Delay in seconds between commands")
	commandFile := flag.String("command-file", "", "File with commands to run")

	flag.Parse()

	if *commandFile != "" {
		if *cmds != "" {
			log.Fatalf("Specify either -c (commands) or -command-file, not both")
		}
		fileCmds, err := readCommandsFromFile(*commandFile)
		if err != nil {
			log.Fatalf("Error reading commands from file: %s", err)
		}
		*cmds = strings.Join(fileCmds, ",")
	}

	config := SSHClientConfig{
		Host:              *host,
		User:              *user,
		Password:          *password,
		Cmds:              strings.Split(*cmds, ","),
		InvokeShell:       *invokeShell,
		Prompt:            *prompt,
		PromptCount:       *promptCount,
		Timeout:           *timeoutDuration,
		Ciphers:           strings.Split(*ciphers, ","),
		KeyExchanges:      strings.Split(*keyExchanges, ","),
		HostKeyAlgos:      strings.Split(*hostKeyAlgos, ","),
		IntercommandDelay: *intercommandDelay,
	}

	realClient := RealSSHClient{}
	output, err := ExecuteSSHCommands(&realClient, config)
	if err != nil {
		log.Fatalf("Error executing SSH commands: %s", err)
	}

	fmt.Println(output)
}
