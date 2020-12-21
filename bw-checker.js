/**
 * @author Hendrik Legge <hendrik.legge@themepoint.de>
 * @version 1.0.0.0
 **/

const { execSync } = require("child_process");
const crypto = require('crypto');
const https = require('https');

module.exports = class BwChecker {
    constructor(
        session = null,
        login = false,
        host = null,
        username = null,
        password = null
    ) {
        this.host = host;
        this.username = username;
        this.password = password;
        this.useLogin = login;
        this.session = session;
    }

    execute() {
        if (this.useLogin) {
            this.login();
        }

        if (this.session === null) {
            console.error('\x1b[31m[SERVICE] Session not found.\x1b[0m');
            return;
        }

        let itemsRaw = this.runCommand('bw list items --session ' + this.session);
        let items = JSON.parse(itemsRaw);

        let self = this;
        items.forEach(function (object, key) {
            if (object.type === 1) {
                let hash = self.createPasswordHash(object.login.password)

                if (hash === null) {
                    console.error('\x1b[31m' + object.name + ' - Failed to generate hash for entry\x1b[0m');
                    return;
                }

                self.sendPwnedRequest(hash.slice(0,5), hash, key, object);
            }
        });
    }

    sendPwnedRequest(requestHash, hash, key, object) {
        let suffix = hash.slice(5)
        let match = new RegExp(`^${suffix}:`, 'm')

        https.get('https://api.pwnedpasswords.com/range/' + requestHash, (resp) => {
            let data = '';

            resp.on('data', (chunk) => {
                data += chunk;
            });

            resp.on('end', () => {

                if (match.test(data)) {
                    console.error('\x1b[31m[PWNED]\x1b[0m\x1b[36m - ' + object.name + ' - \x1b[0m\x1b[31mPassword should be checked as it may be pwned.\x1b[0m \x1b[33m[Hash: ' + hash + ']\x1b[0m');
                } else {
                    console.log('\x1b[32m[SUCCESS]\x1b[0m\x1b[36m - ' + object.name + ' - \x1b[0m\x1b[32mNo threats found.\x1b[0m \x1b[33m[Hash: ' + hash + ']\x1b[0m');
                }
            });

        })

    }

    login() {
        let status = JSON.parse(this.runCommand('bw status'));

        if (status.serverUrl !== this.host) {
            this.runCommand('bw config server ' + this.host);
        }

        if (status.userId !== null) {
            this.runCommand('bw logout');
        }

        let loginResult = this.runCommand('bw login ' + this.username + ' ' + this.password);

        let m;
        const regex = /BW_SESSION="(.*)"/gm;
        let self = this;
        while ((m = regex.exec(loginResult)) !== null) {
            if (m.index === regex.lastIndex) {
                regex.lastIndex++;
            }

            m.forEach((match, groupIndex) => {
                if (groupIndex === 1 && self.session === null) {
                    self.session = match;
                    console.log('\x1b[32m[SERVICE] Create session ' + match + '\x1b[0m');
                }
            });
        }
    }

    createPasswordHash(password) {
        let result = null;

        try {
            result = crypto.createHash('sha1').update(password, "binary").digest('hex').toUpperCase();
        } catch ($e) {}

        return result;
    }

    runCommand(command) {
        return execSync(command, {
            encoding: 'utf-8'
        });
    }
}