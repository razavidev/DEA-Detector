import dns from 'dns'
import net from 'net'

async function isDomainCatchAll(email) {
  const domain = email.split('@')[1];
  if (!domain) {
    return false;
  }

  try {
    const mxRecords = await dns.promises.resolveMx(domain);
    if (mxRecords.length === 0) {
      return false; 
    }

    mxRecords.sort((a, b) => a.priority - b.priority);

    for (const mx of mxRecords) {
      const server = mx.exchange;

      const fakeEmail = `nonexistentuser1234567890@${domain}`;

      const result = await testEmailWithMxServer(server, fakeEmail, domain);
      if (result) {
        console.log(`Domain "${domain}" is a catch-all (detected via ${server})`);
        return true;
      }
    }
  } catch (error) {
    console.error(`Error checking domain ${domain}:`, error);
  }

  console.log(`Domain "${domain}" is likely not a catch-all.`);
  return false;
}

function testEmailWithMxServer(server, email, domain) {
  return new Promise((resolve, reject) => {
    let responded = false;
    let isCatchAll = false;

    const timeout = setTimeout(() => {
      if (!responded) {
        socket.destroy();
        resolve(false);
      }
    }, 5000);

    const socket = net.createConnection(25, server);

    const commands = [
      `EHLO ${domain}`, 
      `MAIL FROM:<noreply@${domain}>`, 
      `RCPT TO:<${email}>`, 
    ];
    let currentCommand = 0;

    socket.on('data', (data) => {
      const response = data.toString();
      console.log(`[${server}] <<< ${response.trim()}`);

      if (currentCommand < commands.length) {
        const cmd = commands[currentCommand];
        console.log(`[${server}] >>> ${cmd}`);
        socket.write(`${cmd}\r\n`);
        currentCommand++;
      }

      if (response.startsWith('250')) {
        if (commands[currentCommand - 1].startsWith('RCPT TO:')) {
          isCatchAll = true;
          socket.write('QUIT\r\n');
        }
      }

      // Check for a negative response to RCPT TO
      if (response.startsWith('550')) {
        
        // A "550 No such user here" is proof it's NOT a catch-all
        isCatchAll = false;
        socket.write('QUIT\r\n');
      }

      // End conversation and resolve
      if (response.includes('221 Bye')) {
        clearTimeout(timeout);
        socket.destroy();
        resolve(isCatchAll);
        responded = true;
      }
    });

    socket.on('error', (err) => {
      console.error(`[${server}] Error:`, err);
      clearTimeout(timeout);
      resolve(false);
    });

    socket.on('close', () => {
      clearTimeout(timeout);
      if (!responded) {
        resolve(isCatchAll);
      }
    });
  });
}

export default isDomainCatchAll
