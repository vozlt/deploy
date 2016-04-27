The asynchronous distribution daemon with rsync.
==========

[![License](http://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/vozlt/deploy/blob/master/LICENSE)

The asynchronous distribution daemon with rsync.

Table of Contents
=================

* [Summary](#summary)
* [Architecture](#architecture)
 * [Programs](#programs)
 * [Flow](#flow)
 * [Build](#build)
 * [Security](#security)
* [Dependencies](#dependencies)
* [Compatibility](#compatibility)
* [Installation](#installation)
* [Running](#running)
 * [deploy-agent](#deploy-agent)
 * [deploy-proxy](#deploy-proxy)
 * [deploy-client](#deploy-client)
* [Configuration](#configuration)
 * [Path](#path)
 * [SSL](#ssl)
 * [Rsync options](#rsync-options)
* [Examples](#examples)
 * [STATUS](#status)
 * [RLIST](#rlist)
 * [RSYNC](#rsync)
 * [RKILL](#rkill)
 * [EXEC](#exec)
* [Author](#author)

## Summary
The deploy is a asynchronous distribution daemon with rsync.
If you have a ssl option(true), then all of data interchange is encrypted.
But if you do not use rsync ssh tunnel, then the file transfer
is not encrypted.

Deploy's features are as follows:
* Asynchronous source distribution with rsync.
* Service daemon control using user defined commands.

## Architecture
### Programs
#### deploy-agent
Deploy agent daemon for synchronization or running user defined commands

#### deploy-proxy
Deploy proxy daemon to relay from deploy-client to deploy-agent.

#### deploy-client
Deploy client to connect to deploy-agent.

### Flow
```
+---------------+      +--------------+
| deploy-client | ---> | deploy-proxy | ----+
+---------------+      +--------------+     |
	   |                                    |
	   |               +--------------+     |
	   +-------------> | deploy-agent | <---+
					   +--------------+
+---------------+             |
|    rsyncd     | <-----------+
+---------------+
```

### Build
#### [deploy-client + deploy-agent]
This is the basic design for that.
```
+---------------+      +--------------+
| deploy-client | ---> | deploy-agent | ----+
+---------------+      +--------------+     |
											|
+---------------+                           |
|    rsyncd     | <-------------------------+
+---------------+
```

#### [deploy-client + deploy-proxy + deploy-agent]
This is optional design for that.
It makes it relay the command from deploy-client to deploy-agent via
deploy-proxy that is similar to the type of api server.
```
+---------------+      +--------------+
| deploy-client | ---> | deploy-proxy | ----+
+---------------+      +--------------+     |
											|
+---------------+      +--------------+     |
|    rsyncd     | <--- | deploy-agent | <---+
+---------------+      +--------------+
```

### Security
The ssl option in config file(/etc/deploy/deploy_(agent|proxy).ini)

* SSL: `false`
 * The transferring data is a plain text.

* SSL: `true`
 * The transferring data is a encrypt string.


## Dependencies
* perl
 * perl-Crypt-OpenSSL-RSA
 * perl-Crypt-OpenSSL-AES
 * perl-Crypt-CBC
 * perl-IPC-ShareLite
* rsync

## Compatibility
* perl-5.10.x ((last tested: v5.10.1)

Earlier versions is not tested.

## Installation

1. Clone the git repository.
 ```
 shell> git clone git://github.com/vozlt/deploy.git
 ```

2. Build the deploy.
 ```
 shell> ./configure
 shell> make
 ```

3. Install the deploy.
 ```
 shell> make install
 ```

## Running

### deploy-agent
```
shell> /usr/sbin/deploy-agent --help
```
```
Usage: deploy-agent [OPTIONS]

Options:
           --path=[path]                        : set server configuration file (default: /etc/deploy/deploy_agent.ini)
           --user=[user]                        : set server running user (defaut: root)
           --group=[group]                      : set server running group (defaut: root)
           --addr=[addr]                        : set server listen address (defaut: 0.0.0.0)
           --port=[port]                        : set server listen port (default: 3440)
           --backlog=[number]                   : set server listen backlog (default: SOMAXCONN)
           --max-prefork=[number]               : limits the maximum worker process number
           --max-requests-per-child=[number]    : limits the maximum requests of child
           --max-process-timeout=[number]       : limits the maximum execution time
           --socket-timeout=[number]            : limits the maximum socket wait time
           --socket-accept-filter=[on|off]      : optimizations for a protocol's listener sockets
           --log-write=[on|off]                 : set logging
           --log-error-level=[number]           : set logging level (0-7)
           --log-error-path=[path]              : set error log path
           --log-access-path=[path]             : set access log path
           --key-cipher=[string]                : set password for authentication
           --ssl-private-key=[path]             : set ssl private key for crypt
           --debug                              : running debug mode
           --help                               : this help
```
```
shell> /usr/sbin/deploy-agent
```
```
$ ps -eo user,pid,cmd --forest | grep deploy
```
```
root     28329 deploy::agent: master process
root     28330  \_ deploy::agent: worker process
```

### deploy-proxy
```
shell> /usr/sbin/deploy-prosy --help
```
```
Usage: deploy-proxy [OPTIONS]

Options:
           --path=[path]                          : set server configuration file (default: /etc/deploy/deploy_proxy.ini)
           --user=[user]                          : set server running user (defaut: root)
           --group=[group]                        : set server running group (defaut: root)
           --addr=[addr]                          : set server listen address (defaut: 0.0.0.0)
           --port=[port]                          : set server listen port (default: 3440)
           --backlog=[number]                     : set server listen backlog (default: SOMAXCONN)
           --max-prefork=[number]                 : limits the maximum worker process number
           --max-requests-per-child=[number]      : limits the maximum requests of child
           --max-process-timeout=[number]         : limits the maximum execution time
           --socket-timeout=[number]              : limits the maximum socket wait time
           --socket-accept-filter=[on|off]        : optimizations for a protocol's listener sockets
           --log-write=[on|off]                   : set logging
           --log-error-level=[number]             : set logging level (0-7)
           --log-error-path=[path]                : set error log path
           --log-access-path=[path]               : set access log path
           --key-cipher=[string]                  : set password for authentication
           --ssl-private-key=[path]               : set ssl private key for encryption between client and proxy
           --client-worker-method=[fork|thread]   : set multi-processing method (default: fork)
           --client-ipc-path=[memory|path]        : set queue path for IPC (default: file)
           --client-port=[number]                 : set the port to connect to agent (default: 3440)
           --client-thread-timeout=[number]       : limits the client's maximum execution time
           --client-socket-timeout=[number]       : limits the client's maximum socket wait time
           --client-key-cipher=[string]           : set password for agent's authentication
           --client-ssl-public-key=[path]         : set ssl public key for encryption between proxy and agent
           --debug                                : running debug mode
           --help                                 : this help
```
```
shell> /usr/sbin/deploy-proxy
```
```
shell> ps -eo user,pid,cmd --forest | grep deploy
```
```
root     28329 deploy::proxy: master process
root     28330  \_ deploy::proxy: worker process
```

### deploy-client
```
shell> /usr/sbin/deploy-client
```
```
Usage: deploy-client [OPTIONS] [COMMANDS]

Commands:
           --order=[status|rlist|rsync|rkill|exec]    : remote command

Options:
           --hosts=[hosts]                            : remote host
           --port=[port]                              : remote port
           --args=[(groups|hosts):string]             : order hosts (proxy)
           --options=[options]                        : order options
           --key-cipher=[string]                      : set password for authentication (agent)
           --api-key=[string]                         : set api key for authentication (proxy)
           --ssl-public-key=[path]                    : set ssl public key for encryption (proxy|agent)
           --ipc-path=[memory|path]                   : set queue path for IPC (default: file)
           --worker-method=[fork|thread]              : set multi-processing method (default: fork)
           --thread-timeout=[number]                  : limits the client's maximum execution time
           --socket-timeout=[number]                  : limits the client's maximum socket wait time
           --debug                                    : running debug mode
           --verbose                                  : verbose print mode
```


## Configuration

### Path
* deploy-agent
 * /etc/deploy/deploy_agent.ini
* deploy-proxy
 * /etc/deploy/deploy_proxy.ini

### SSL
Generate (private|public).pem
```
shell> openssl genrsa 2048 > private.pem
shell> openssl rsa -in private.pem -out public.pem -outform PEM -pubout
```

### Rsync options
{force_flags} is static options to generate the results of rsync.

{default_flags} is a default options.(If you set option[] in config file, then they will be removed)

They are as follows:
* force_flags
 * --stats
 * --verbose
* default_flags
 * --archive
 * --delete
 * --force

## Examples
If agent's ssl option is true, then you need to set --ssl-public-key option.
If agent's key_cipher option is set, then you need to set --key-cipher option. (Default key_cipher: 65535) 
The below --options={rsync_group_name} first be defined in config file(/etc/deploy/deploy_agent.ini) like "[rsync::group::rsync_group_name].

### STATUS
`Description:` Print the statistics about to be transferred files.

Order to deploy-agent
```
shell> deploy-client --hosts={agent_host} --port=3440 --options={rsync_group_name} --order=status --key-cipher={key}
```
```
shell> deploy-client --hosts={agent_host} --port=3440 --options=hostname::DEST,/path/to --order=status --key-cipher={key}
```

Order to deploy-proxy
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options={rsync_group_name} --order=status --key-cipher={key}
```
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options="hostname::DEST,/path/to" --order=status --key-cipher={key}
```

Results
```Json
{  
   "targethost" : {
	  "status" : {
		 "serverStatus" : 1,
		 "returnCode" : "200",
		 "content" : {
			"transferFilesSize" : "24854724",
			"transferFilesCount" : "328",
			"alreadyRsync" : "false",
			"return" : "true"
		 },
		 "returnString" : "OK",
		 "return" : 1
	  }
   }
}

```

### RLIST
`Description:` Print the list about to be transferred files.

Order to deploy-agent
```
shell> deploy-client --hosts={agent_host} --port=3440 --options={rsync_group_name} --order=rlist --key-cipher={key}
```
```
shell> deploy-client --hosts={agent_host} --port=3440 --options=hostname::DEST,/path/to --order=rlist --key-cipher={key}
```

Order to deploy-proxy
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options={rsync_group_name} --order=rlist --key-cipher={key}
```
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options="hostname::DEST,/path/to" --order=rlist --key-cipher={key}
```

Results
```Json
{  
   "targethost" : {
	  "rlist" : {
		 "serverStatus" : 1,
		 "returnCode" : "200",
		 "content" : {
			"transferDeleteFiles" : [],
			"transferFilesSize" : "24854724",
			"transferFilesCount" : "328",
			"transferNewFiles" : [
			   "created directory /path/to",
			   "file1",
			   "path/file2",
				.
				.
				.
			],
			"return" : "true"
		 },
		 "returnString" : "OK",
		 "return" : 1
	  }
   }
}
```

### RSYNC
`Description:` Run file sync.

Order to deploy-agent
```
shell> deploy-client --hosts={agent_host} --port=3440 --options={rsync_group_name} --order=rsync --key-cipher={key}
```
```
shell> deploy-client --hosts={agent_host} --port=3440 --options=hostname::DEST,/path/to --order=rsync --key-cipher={key}
```

Order to deploy-proxy
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options={rsync_group_name} --order=rsync --key-cipher={key}
```
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options="hostname::DEST,/path/to" --order=rsync --key-cipher={key}
```

Results
```Json
{  
   "targethost" : {
	  "rsync" : {
		 "serverStatus" : 1,
		 "returnCode" : "200",
		 "content" : {
			"checksum" : "e726ab0da49b1b259d3159980d4212a0",
			"return" : "true"
		 },
		 "returnString" : "OK",
		 "return" : 1
	  }
   }
}
```

### RKILL
`Description:` Stop file sync.

Order to deploy-agent
```
shell> deploy-client --hosts={agent_host} --port=3440 --options={rsync_group_name} --order=rkill --key-cipher={key}
```
```
shell> deploy-client --hosts={agent_host} --port=3440 --options=hostname::DEST,/path/to --order=rkill --key-cipher={key}
```

Order to deploy-proxy
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options={rsync_group_name} --order=rkill --key-cipher={key}
```
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options="hostname::DEST,/path/to" --order=rkill --key-cipher={key}
```

Results
```Json
{
   "targethost" : {
	  "rkill" : {
		 "serverStatus" : 1,
		 "returnCode" : "200",
		 "content" : {
			"process" : [],
			"return" : "true"
		 },
		 "returnString" : "OK",
		 "return" : 1
	  }
   }
}
```

### EXEC
`Description:` Run user defined command.

The below --options=service:nginx,restart first be defined in config file like "service:nginx = /etc/init.d/nginx %s".
The command's arguments are separated by commas(,).

Order to deploy-agent
```
shell> deploy-client --hosts={agent_host} --port=3440 --options=service:nginx,restart --order="exec" --key-cipher={key}
```

Order to deploy-proxy
```
shell> deploy-client --api-key={key} --hosts={proxy_host} --port=3441 --args={hosts|groups}:{agent_host|agent_host_group} --options=service:nginx,restart --order=exec --key-cipher={key}
```


Results
```Json
{  
   "targethost" : {
	  "exec" : {
		 "serverStatus" : 1,
		 "returnCode" : "200",
		 "content" : {
			"content" : "U3RvcHBpbmcgbmdpbng6ICAgICAgICAgWyAgT0sgIF0NClN0YXJ0aW5nIG5naW54OiAgICAgICAgIFsgIE9LICBd",
			"command" : "L2V0Yy9pbml0LmQvbmdpbnggcmVzdGFydA==",
			"return" : "true"
		 },
		 "returnString" : "OK",
		 "return" : 1
	  }
   }
}
```

## Author
YoungJoo.Kim(김영주) [<vozltx@gmail.com>]
