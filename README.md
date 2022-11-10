# ssh-pub
The code for ssh-pub.pcprojects.tk. Hostkeys and database sold separately.

## Building
Can be run on Windows. Linux isn't tested.

### Step 1: create db.json

```json
{
	"guest": {
		"password": "",
		"admin": false,
		"readonly": true,
		"banned": false
	},
	"root": {
		"password": "EnterYourNewRootPasswordWithSHA256Hashing",
		"admin": true,
		"readonly": false,
		"banned": false
	}
 }
```

### Step 2: create hostkeys

Requires OpenSSH.

`ssh-keygen [preferable options here]`

Save as `./hostkeys`.

### Step 3: install npm package `ssh2`

`npm install ssh2`

### Step 4: Run the server.

In an unstable environment `ssh_start.cmd` or any other simple `while(true)` can auto-restart the process.
